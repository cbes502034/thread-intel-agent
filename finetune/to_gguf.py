"""Qwen2 系列 Hugging Face 權重（safetensors）→ GGUF，供 Ollama 匯入。

為什麼自己寫：本機 Ollama（0.40.x）從 safetensors 匯入時走 MLX 路徑，不支援 Qwen2 架構，
所以先轉成 GGUF（Ollama／llama.cpp 的標準模型格式）再匯入。這裡只用官方 gguf 套件
（pip install gguf）的寫檔 API：寫入超參數、詞表、權重張量，必要時做 Q8_0 量化。

用法：python -m finetune.to_gguf <模型資料夾> <輸出.gguf> [--outtype q8_0|f16]
"""
import argparse
import json
from pathlib import Path

import gguf
import numpy as np
import torch
from safetensors import safe_open
from transformers import AutoTokenizer


def write_vocab(writer, model_dir, vocab_size):
    tok = AutoTokenizer.from_pretrained(model_dir)
    reverse = {i: t for t, i in tok.get_vocab().items()}
    added = tok.get_added_vocab()
    decoder = tok.added_tokens_decoder
    tokens, types = [], []
    for i in range(vocab_size):
        if i not in reverse:                                   # 詞表補齊到 embedding 大小
            tokens.append(f"[PAD{i}]")
            types.append(gguf.TokenType.UNUSED)
            continue
        t = reverse[i]
        if t in added:
            special = decoder[i].special if i in decoder else False
            types.append(gguf.TokenType.CONTROL if special else gguf.TokenType.USER_DEFINED)
        else:
            types.append(gguf.TokenType.NORMAL)
        tokens.append(t)
    writer.add_tokenizer_model("gpt2")
    writer.add_tokenizer_pre("qwen2")
    writer.add_token_list(tokens)
    writer.add_token_types(types)
    gguf.SpecialVocab(model_dir, load_merges=True).add_to_gguf(writer)   # merges、eos/pad、chat template


def convert(model_dir, out_path, outtype="q8_0"):
    model_dir = Path(model_dir)
    cfg = json.loads((model_dir / "config.json").read_text(encoding="utf-8"))
    n_layers = cfg["num_hidden_layers"]
    q8 = outtype == "q8_0"

    writer = gguf.GGUFWriter(str(out_path), gguf.MODEL_ARCH_NAMES[gguf.MODEL_ARCH.QWEN2])
    writer.add_name(Path(out_path).stem)
    writer.add_context_length(cfg["max_position_embeddings"])
    writer.add_embedding_length(cfg["hidden_size"])
    writer.add_block_count(n_layers)
    writer.add_feed_forward_length(cfg["intermediate_size"])
    writer.add_head_count(cfg["num_attention_heads"])
    writer.add_head_count_kv(cfg["num_key_value_heads"])
    writer.add_rope_freq_base(cfg.get("rope_theta", 1000000.0))
    writer.add_layer_norm_rms_eps(cfg["rms_norm_eps"])
    writer.add_file_type(gguf.LlamaFileType.MOSTLY_Q8_0 if q8 else gguf.LlamaFileType.MOSTLY_F16)
    write_vocab(writer, model_dir, cfg["vocab_size"])

    name_map = gguf.get_tensor_name_map(gguf.MODEL_ARCH.QWEN2, n_layers)
    count = 0
    for shard in sorted(model_dir.glob("*.safetensors")):
        with safe_open(shard, framework="pt") as f:
            for hf_name in f.keys():
                if hf_name == "lm_head.weight" and cfg.get("tie_word_embeddings"):
                    continue                                    # 共用 embedding，不另存輸出層
                new_name = name_map.get_name(hf_name, try_suffixes=(".weight", ".bias"))
                if new_name is None:
                    raise ValueError(f"無法對應張量名稱：{hf_name}")
                data = f.get_tensor(hf_name).to(torch.float32).numpy()
                if data.ndim == 1:                              # norm、bias 保持 F32
                    writer.add_tensor(new_name, data.astype(np.float32))
                elif q8 and data.shape[-1] % 32 == 0:
                    qdata = gguf.quants.quantize(data, gguf.GGMLQuantizationType.Q8_0)
                    writer.add_tensor(new_name, qdata, raw_dtype=gguf.GGMLQuantizationType.Q8_0)
                else:
                    writer.add_tensor(new_name, data.astype(np.float16))
                count += 1

    writer.write_header_to_file()
    writer.write_kv_data_to_file()
    writer.write_tensors_to_file()
    writer.close()
    size = Path(out_path).stat().st_size / 1e6
    print(f"已寫入 {count} 個張量 → {out_path}（{size:.0f} MB，{outtype}）")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("model_dir")
    ap.add_argument("out")
    ap.add_argument("--outtype", default="q8_0", choices=["q8_0", "f16"])
    a = ap.parse_args()
    convert(a.model_dir, a.out, a.outtype)
