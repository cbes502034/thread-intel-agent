"""LoRA 微調（純 CPU 可跑）。

基底：Qwen/Qwen2.5-0.5B-Instruct（finetune/artifacts/base）
方法：凍結全部原始權重，只在「後半段 12 層」的注意力與 MLP 投影矩陣旁訓練低秩增量。
損失：只算 assistant 段（報告 JSON）的 token，提示部分不算。

為了讓沒有獨顯的筆電也跑得完，做了三個取捨（第一版約需 8.5 小時，改完約 1.5 小時）：
1. LoRA 只掛在後 12 層：反向傳播只需走到第 12 層，前半段只做前向，省下約三分之一運算。
2. 只對答案位置計算 logits：詞表有 15 萬個 token，對 800 個提示 token 算 logits 是純浪費。
3. 不開 gradient checkpointing：只有後半段要存活化值，記憶體夠用，省掉重算。

用法：python -m finetune.train_lora [--epochs 1] [--limit 400] [--threads 6] [--bench 3] [--resume]
輸出：finetune/artifacts/lora/（adapter）、training_log.jsonl、train_state.json
"""
import argparse
import json
import math
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

import torch
import torch.nn.functional as F
from peft import LoraConfig, PeftModel, get_peft_model
from torch.optim import AdamW
from transformers import AutoModelForCausalLM, AutoTokenizer

HERE = Path(__file__).parent
BASE = HERE / "artifacts" / "base"
OUT = HERE / "artifacts" / "lora"
LOG = HERE / "artifacts" / "training_log.jsonl"
STATE = HERE / "artifacts" / "train_state.json"
MAX_LEN = 2048


def encode(tokenizer, messages):
    """chat 樣本 → (input_ids, 答案起點)。"""
    prompt_text = tokenizer.apply_chat_template(messages[:-1], tokenize=False, add_generation_prompt=True)
    prompt_ids = tokenizer(prompt_text, add_special_tokens=False)["input_ids"]
    answer_ids = tokenizer(messages[-1]["content"] + "<|im_end|>", add_special_tokens=False)["input_ids"]
    ids = prompt_ids + answer_ids
    return (ids, len(prompt_ids)) if len(ids) <= MAX_LEN else None


def load_rows(tokenizer, split, limit=None, seed=42):
    rows = []
    for line in (HERE / f"sft_{split}.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        enc = encode(tokenizer, r["messages"])
        if enc:
            rows.append((r["id"].rsplit("_", 1)[0], enc))
    if limit and limit < len(rows):
        # 依情境分層抽樣，確保每種情境（門檻邊界、查詢失敗、私有位址…）都有代表
        groups = defaultdict(list)
        for scen, enc in rows:
            groups[scen].append(enc)
        rng = random.Random(seed)
        picked = []
        for scen, items in sorted(groups.items()):
            rng.shuffle(items)
            picked += items[:max(1, round(len(items) * limit / len(rows)))]
        rows = [("", e) for e in picked]
    return [enc for _, enc in rows]


def answer_loss(model, ids, start):
    """只在答案位置算 logits 與交叉熵。"""
    inner = model.get_base_model()          # Qwen2ForCausalLM（LoRA 已注入其中）
    x = torch.tensor([ids])
    hidden = inner.model(input_ids=x, use_cache=False).last_hidden_state   # (1, L, H)
    logits = inner.lm_head(hidden[:, start - 1:-1, :])        # 預測 ids[start:]
    target = x[:, start:]
    return F.cross_entropy(logits.reshape(-1, logits.size(-1)).float(), target.reshape(-1))


@torch.no_grad()
def eval_loss(model, rows):
    model.eval()
    vals = [answer_loss(model, ids, s).item() for ids, s in rows]
    model.train()
    return sum(vals) / max(len(vals), 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--limit", type=int, help="訓練樣本數上限（分層抽樣）")
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--accum", type=int, default=4)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--layers-from", type=int, default=12, help="LoRA 掛在第幾層之後（0 = 全部 24 層）")
    ap.add_argument("--threads", type=int, default=6)
    ap.add_argument("--eval-n", type=int, default=16)
    ap.add_argument("--eval-every", type=int, default=25)
    ap.add_argument("--bench", type=int, help="只量測 N 個樣本的單步耗時後結束")
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()

    torch.set_num_threads(args.threads)
    torch.manual_seed(42)
    random.seed(42)
    tokenizer = AutoTokenizer.from_pretrained(BASE)
    model = AutoModelForCausalLM.from_pretrained(BASE, dtype=torch.float32)
    n_layers = model.config.num_hidden_layers
    state = json.loads(STATE.read_text()) if (args.resume and STATE.exists()) else {"step": 0, "best": None}
    if args.resume and (OUT / "adapter_model.safetensors").exists():
        model = PeftModel.from_pretrained(model, OUT, is_trainable=True)
        print(f"從 step {state['step']} 續訓")
    else:
        state = {"step": 0, "best": None}
        model = get_peft_model(model, LoraConfig(
            r=args.rank, lora_alpha=args.rank * 2, lora_dropout=0.05, task_type="CAUSAL_LM",
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
            layers_to_transform=list(range(args.layers_from, n_layers))))
    model.print_trainable_parameters()
    model.train()

    train_rows = load_rows(tokenizer, "train", args.limit)
    val_rows = load_rows(tokenizer, "val")[: args.eval_n]
    params = [p for p in model.parameters() if p.requires_grad]

    if args.bench:
        t = time.time()
        for ids, s in train_rows[: args.bench]:
            answer_loss(model, ids, s).backward()
        per = (time.time() - t) / args.bench
        est = per * len(train_rows) * args.epochs / 3600
        print(f"[bench] threads={args.threads} layers_from={args.layers_from} "
              f"每樣本 {per:.1f}s；{len(train_rows)} 筆 × {args.epochs} epoch ≈ {est:.2f} 小時")
        return

    steps_total = math.ceil(len(train_rows) * args.epochs / args.accum)
    warmup = max(1, steps_total // 20)
    optim = AdamW(params, lr=args.lr, weight_decay=0.0)
    lr_at = lambda s: (s + 1) / warmup if s < warmup else 0.5 * (1 + math.cos(math.pi * (s - warmup) / max(1, steps_total - warmup)))
    sched = torch.optim.lr_scheduler.LambdaLR(optim, lr_at)
    for _ in range(state["step"]):
        sched.step()

    LOG.parent.mkdir(parents=True, exist_ok=True)
    log_f = LOG.open("a", encoding="utf-8")
    t0 = time.time()

    def log(**kw):
        kw["t"] = round(time.time() - t0, 1)
        log_f.write(json.dumps(kw, ensure_ascii=False) + "\n")
        log_f.flush()
        print(kw, flush=True)

    def save(step, val):
        model.save_pretrained(OUT)
        STATE.write_text(json.dumps({"step": step, "best": val}))

    log(event="start", train=len(train_rows), val=len(val_rows), steps=steps_total, lr=args.lr,
        accum=args.accum, rank=args.rank, layers_from=args.layers_from, threads=args.threads,
        resume_from=state["step"])
    if state["step"] == 0:
        log(event="eval", step=0, val_loss=round(eval_loss(model, val_rows), 4))

    rng = random.Random(1000 + state["step"])
    order, step, micro, running = [], state["step"], 0, 0.0
    best = state["best"] if state["best"] is not None else float("inf")
    while step < steps_total:
        if not order:
            order = rng.sample(range(len(train_rows)), len(train_rows))
        ids, s = train_rows[order.pop()]
        loss = answer_loss(model, ids, s)
        (loss / args.accum).backward()
        running += loss.item()
        micro += 1
        if micro % args.accum:
            continue
        torch.nn.utils.clip_grad_norm_(params, 1.0)
        optim.step()
        sched.step()
        optim.zero_grad(set_to_none=True)
        step += 1
        if step % 5 == 0:
            log(event="train", step=step, loss=round(running / (5 * args.accum), 4),
                lr=round(sched.get_last_lr()[0], 7))
            running = 0.0
        if step % args.eval_every == 0 or step == steps_total:
            vl = eval_loss(model, val_rows)
            log(event="eval", step=step, val_loss=round(vl, 4))
            if vl < best:
                best = vl
                save(step, vl)
                log(event="save", step=step, val_loss=round(vl, 4))
            else:
                STATE.write_text(json.dumps({"step": step, "best": best}))
    log(event="done", best_val_loss=round(best, 4), hours=round((time.time() - t0) / 3600, 2))


if __name__ == "__main__":
    main()
