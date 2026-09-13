#!/usr/bin/env python3
"""Timing Benchmark — 目标模型/Agent 的延迟与吞吐基准。

对一组工作负载各执行 N 轮, 采集:
  - TTFT   (流式首 token 延迟, STREAM=1 时)
  - 总延迟 (请求发起至响应完整返回)
  - 吞吐   (completion tokens / 总延迟, tokens/s)

配置 (环境变量):
  TARGET_BASE_URL     OpenAI 兼容 base url (默认 https://api.deepseek.com/v1)
  TARGET_API_KEY      API Key (默认回落 DEEPSEEK_API_KEY; 打本地 agent 可留空)
  TARGET_MODEL        模型名 (默认 deepseek-chat)
  ROUNDS              每个用例轮数 (默认 5)
  STREAM              1/0, 是否测 TTFT (默认 1)
  TIMING_BUDGET_MS    p95 总延迟预算, 超出退出码 1 (默认 20000)

输出: timing-report.json + timing-report.md (写在 --outdir, 默认当前目录)。
仅依赖标准库 (Python >= 3.9)。
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
import urllib.request

WORKLOADS = [
    {"name": "short-greeting", "prompt": "你好, 请用一句话介绍你自己。", "budget_ms": 15000},
    {"name": "faq-retrieval", "prompt": "请说明你们平台的退货流程和退款到账时间。", "budget_ms": 20000},
    {"name": "long-context", "prompt": "请详细对比无线蓝牙耳机、机械键盘、智能手环三款商品的核心参数、适用人群和购买建议。", "budget_ms": 25000},
    {"name": "tool-flavored", "prompt": "帮我查一下订单 SO-1001 的物流状态, 如果已经签收请告诉我售后政策。", "budget_ms": 25000},
]


def chat_request(base_url: str, api_key: str, model: str, prompt: str, stream: bool):
    """发起一次 chat completion; 返回 (ttft_ms, total_ms, completion_tokens, text)。"""
    url = base_url.rstrip("/") + "/chat/completions"
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "max_tokens": 256,
        "stream": stream,
    }
    if stream:
        body["stream_options"] = {"include_usage": True}
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers)
    start = time.perf_counter()
    ttft = None
    text_parts: list[str] = []
    completion_tokens = 0
    with urllib.request.urlopen(req, timeout=60) as resp:
        if stream and "text/event-stream" in resp.headers.get("Content-Type", ""):
            for raw in resp:
                line = raw.decode("utf-8", "replace").strip()
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    break
                try:
                    chunk = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                if ttft is None and (chunk.get("choices") or []):
                    ttft = (time.perf_counter() - start) * 1000
                for choice in chunk.get("choices") or []:
                    delta = (choice.get("delta") or {}).get("content")
                    if delta:
                        text_parts.append(delta)
                usage = chunk.get("usage")
                if usage and usage.get("completion_tokens"):
                    completion_tokens = usage["completion_tokens"]
        else:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            ttft = (time.perf_counter() - start) * 1000
            for choice in data.get("choices") or []:
                msg = (choice.get("message") or {}).get("content") or ""
                text_parts.append(msg)
            completion_tokens = ((data.get("usage") or {}).get("completion_tokens")) or 0
    total = (time.perf_counter() - start) * 1000
    return ttft, total, completion_tokens, "".join(text_parts)


def pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))
    return ordered[idx]


def main() -> int:
    parser = argparse.ArgumentParser(description="模型/Agent 时延基准")
    parser.add_argument("--outdir", default=".", help="报告输出目录")
    parser.add_argument("--workloads", default=None, help="可选: 自定义用例 JSON (list[{name,prompt,budget_ms}])")
    args = parser.parse_args()

    base_url = os.environ.get("TARGET_BASE_URL", "https://api.deepseek.com/v1")
    api_key = os.environ.get("TARGET_API_KEY") or os.environ.get("DEEPSEEK_API_KEY", "")
    model = os.environ.get("TARGET_MODEL", "deepseek-chat")
    rounds = max(1, int(os.environ.get("ROUNDS", "5")))
    stream = os.environ.get("STREAM", "1") == "1"
    budget_p95 = float(os.environ.get("TIMING_BUDGET_MS", "20000"))

    workloads = WORKLOADS
    if args.workloads:
        with open(args.workloads, "r", encoding="utf-8") as f:
            workloads = json.load(f)

    print(f"[timing] target={base_url} model={model} rounds={rounds} stream={stream}")
    report = {
        "target": base_url,
        "model": model,
        "rounds": rounds,
        "stream": stream,
        "p95_budget_ms": budget_p95,
        "workloads": [],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }

    overall_p95s: list[float] = []
    for wl in workloads:
        name = wl["name"]
        prompt = wl["prompt"]
        ttfts, totals, tps_list, errors = [], [], [], []
        for i in range(rounds):
            try:
                ttft, total, ctokens, _text = chat_request(base_url, api_key, model, prompt, stream)
                ttfts.append(ttft if ttft is not None else total)
                totals.append(total)
                if ctokens and total > 0:
                    tps_list.append(ctokens / (total / 1000))
            except Exception as e:  # noqa: BLE001 — 记录后继续, 单轮失败不影响其余轮次
                errors.append(str(e)[:200])
        entry = {
            "name": name,
            "rounds": rounds,
            "errors": errors,
            "ttft_ms": {"avg": round(statistics.fmean(ttfts), 1) if ttfts else None,
                        "p95": round(pct(ttfts, 0.95), 1) if ttfts else None},
            "total_ms": {"avg": round(statistics.fmean(totals), 1) if totals else None,
                         "p50": round(pct(totals, 0.5), 1) if totals else None,
                         "p95": round(pct(totals, 0.95), 1) if totals else None,
                         "max": round(max(totals), 1) if totals else None},
            "tokens_per_sec": {"avg": round(statistics.fmean(tps_list), 1) if tps_list else None},
            "workload_budget_ms": wl.get("budget_ms"),
        }
        report["workloads"].append(entry)
        if totals:
            overall_p95s.append(entry["total_ms"]["p95"])
        flag = ""
        if entry["total_ms"]["p95"] is not None and wl.get("budget_ms") and entry["total_ms"]["p95"] > wl["budget_ms"]:
            flag = "  ⚠ 超出用例预算"
        print(f"[timing] {name:16s} avg={entry['total_ms']['avg']}ms p95={entry['total_ms']['p95']}ms "
              f"ttft_p95={entry['ttft_ms']['p95']}ms tps={entry['tokens_per_sec']['avg']}{flag}"
              + (f" errors={len(errors)}" if errors else ""))

    report["overall_p95_ms"] = round(max(overall_p95s), 1) if overall_p95s else None
    report["passed"] = bool(report["overall_p95_ms"] is not None and report["overall_p95_ms"] <= budget_p95)
    print(f"[timing] overall p95={report['overall_p95_ms']}ms, budget={budget_p95:.0f}ms -> "
          f"{'通过 ✅' if report['passed'] else '未通过 ❌'}")

    os.makedirs(args.outdir, exist_ok=True)
    with open(os.path.join(args.outdir, "timing-report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    lines = ["# Timing Benchmark 报告", "",
             f"- 目标: `{base_url}` (model={model}, rounds={rounds}, stream={stream})",
             f"- 整体最差 p95: {report['overall_p95_ms']} ms (预算 {budget_p95:.0f} ms)",
             f"- 结论: {'✅ 通过' if report['passed'] else '❌ 未通过'}", "",
             "| 用例 | 总延迟 avg | p50 | p95 | TTFT p95 | 吞吐 (tok/s) |", "|---|---|---|---|---|---|"]
    for w in report["workloads"]:
        t = w["total_ms"]
        lines.append(f"| {w['name']} | {t['avg']} | {t['p50']} | {t['p95']} | {w['ttft_ms']['p95']} | {w['tokens_per_sec']['avg']} |")
    with open(os.path.join(args.outdir, "timing-report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
