"""合併 LoRA → 轉 GGUF → 匯入 Ollama 成為 threat-intel-judge。

步驟：
1. 基底權重 + LoRA adapter 合併（merge_and_unload），存成 safetensors
2. finetune/to_gguf.py 轉成 GGUF（Q8_0 量化，531 MB，CPU 推論快、品質幾乎無損）
3. 產生 Modelfile（Qwen 對話模板、temperature 0、停止符號）並 ollama create
4. 刪掉中間產物 merged/（約 1 GB），保留 .gguf 方便搬到其他機器

用法：python -m finetune.export_ollama [--name threat-intel-judge] [--keep-merged]
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

from finetune.to_gguf import convert

ART = Path(__file__).parent / "artifacts"
BASE, LORA, MERGED = ART / "base", ART / "lora", ART / "merged"

# Qwen2.5 對話模板（取自 ollama show qwen2.5 --modelfile，去掉工具段——判定模型不用工具）
TEMPLATE = '''TEMPLATE """{{- if .Messages }}
{{- if .System }}<|im_start|>system
{{ .System }}<|im_end|>
{{ end }}
{{- range $i, $_ := .Messages }}
{{- $last := eq (len (slice $.Messages $i)) 1 -}}
{{- if eq .Role "user" }}<|im_start|>user
{{ .Content }}<|im_end|>
{{ else if eq .Role "assistant" }}<|im_start|>assistant
{{ .Content }}{{ if not $last }}<|im_end|>
{{ end }}
{{- end }}
{{- if and (ne .Role "assistant") $last }}<|im_start|>assistant
{{ end }}
{{- end }}
{{- else }}
{{- if .System }}<|im_start|>system
{{ .System }}<|im_end|>
{{ end }}{{ if .Prompt }}<|im_start|>user
{{ .Prompt }}<|im_end|>
{{ end }}<|im_start|>assistant
{{ end }}{{ .Response }}{{ if .Response }}<|im_end|>{{ end }}"""'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="threat-intel-judge")
    ap.add_argument("--keep-merged", action="store_true")
    args = ap.parse_args()

    print("1/3 合併 LoRA…", flush=True)
    model = AutoModelForCausalLM.from_pretrained(BASE, dtype=torch.float32)
    model = PeftModel.from_pretrained(model, LORA).merge_and_unload()
    model.to(torch.float16).save_pretrained(MERGED)
    AutoTokenizer.from_pretrained(BASE).save_pretrained(MERGED)
    del model

    gguf_path = ART / f"{args.name}-q8_0.gguf"
    print("2/3 轉成 GGUF…", flush=True)
    convert(MERGED, gguf_path, "q8_0")

    modelfile = ART / "Modelfile"
    modelfile.write_text(
        f"FROM {gguf_path.as_posix()}\n{TEMPLATE}\n"
        "PARAMETER temperature 0\n"
        "PARAMETER num_ctx 4096\n"
        'PARAMETER stop "<|im_end|>"\n'
        'PARAMETER stop "<|endoftext|>"\n'
        'LICENSE """Built with Qwen. Qwen2.5-0.5B-Instruct is licensed under Apache-2.0."""\n',
        encoding="utf-8")
    print("3/3 ollama create…", flush=True)
    r = subprocess.run(["ollama", "create", args.name, "-f", str(modelfile)], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        sys.exit(f"ollama create 失敗（exit {r.returncode}）：{r.stderr[-800:]}")
    if not args.keep_merged:
        shutil.rmtree(MERGED, ignore_errors=True)
    print(f"完成：Ollama 模型 {args.name}（GGUF 保留在 {gguf_path}）")


if __name__ == "__main__":
    main()
