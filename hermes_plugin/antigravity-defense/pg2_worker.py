#!/usr/bin/env python3
"""Prompt Guard 2 (Llama-Prompt-Guard-2-86M-tr-v2) Subprocess Worker for Hermes Agent.

Provides zero-VRAM (CPU-only) prompt-injection scoring for untrusted tool outputs.
Communicates strictly via stdin/stdout line-delimited JSON (no network ports).
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# Enforce zero-VRAM CPU-only execution and prevent tokenizer threading deadlocks
os.environ["CUDA_VISIBLE_DEVICES"] = ""
os.environ["TOKENIZERS_PARALLELISM"] = "false"

if hasattr(sys.stdin, "reconfigure"):
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


DEFAULT_MODEL_DIR = Path(
    r"D:\PROJELER\Antigravity_Defense_Suite\1_Devam_Eden\modeller\Llama-Prompt-Guard-2-86M-tr-v2"
)


def resolve_model_dir() -> Path:
    if len(sys.argv) > 1 and sys.argv[1].strip():
        return Path(sys.argv[1].strip())
    env_dir = os.environ.get("AG_PG2_MODEL_DIR", "").strip()
    if env_dir:
        return Path(env_dir)
    return DEFAULT_MODEL_DIR


def main() -> None:
    model_dir = resolve_model_dir()
    if not model_dir.is_dir() or not (model_dir / "config.json").is_file():
        err_resp = {
            "status": "error",
            "message": f"Model directory not found or missing config.json: {model_dir}",
        }
        sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
        sys.stdout.flush()
        sys.exit(1)

    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        t0 = time.time()
        tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
        model = AutoModelForSequenceClassification.from_pretrained(str(model_dir))
        model.eval()
        load_time = time.time() - t0

        ready_resp = {
            "status": "ready",
            "model_dir": str(model_dir),
            "load_time_ms": round(load_time * 1000, 1),
        }
        sys.stdout.write(json.dumps(ready_resp, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    except Exception as exc:
        err_resp = {"status": "error", "message": f"Model initialization failed: {exc}"}
        sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
        sys.stdout.flush()
        sys.exit(1)

    bos_id = tokenizer.bos_token_id if tokenizer.bos_token_id is not None else 1
    eos_id = tokenizer.eos_token_id if tokenizer.eos_token_id is not None else 2
    chunk_size = 510  # 510 tokens + 2 special tokens = 512 max length

    while True:
        line = sys.stdin.readline()
        if not line:
            break
        stripped = line.strip()
        if not stripped:
            continue

        req_id = None
        try:
            req_data = json.loads(stripped)
            req_id = req_data.get("id")
            text = req_data.get("text", "")

            if not text or not isinstance(text, str):
                resp = {"id": req_id, "p_attack": 0.0, "chunks": 0}
            else:
                raw_ids = tokenizer.encode(text, add_special_tokens=False)
                if not raw_ids:
                    chunks = [[]]
                else:
                    chunks = [
                        raw_ids[i : i + chunk_size]
                        for i in range(0, len(raw_ids), chunk_size)
                    ]

                max_p = 0.0
                for chunk in chunks:
                    chunk_ids = [bos_id] + chunk + [eos_id]
                    tensor_in = torch.tensor([chunk_ids], dtype=torch.long)
                    with torch.no_grad():
                        logits = model(tensor_in).logits
                        prob = torch.softmax(logits, dim=-1)[0][1].item()
                    if prob > max_p:
                        max_p = prob

                resp = {
                    "id": req_id,
                    "p_attack": round(max_p, 4),
                    "chunks": len(chunks),
                }
        except Exception as exc:
            resp = {"id": req_id, "p_attack": 0.0, "error": str(exc)}

        sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
