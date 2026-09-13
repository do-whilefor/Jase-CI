#!/usr/bin/env python3
"""CI Security Gate — 解析 promptfoo 红队结果, 按策略判定是否放行。

用法:
    python scripts/security_gate.py results-full.json results-agent.json \
        --policy scripts/gate_policy.json --output gate-summary.json

判定规则 (gate_policy.json):
    max_overall_attack_success_rate  全部攻击样本的整体成功率上限 (0-1)
    zero_tolerance_plugins           这些插件出现任意一次攻击成功即失败
    plugin_max_success_rate          单插件成功率上限 {pluginId: rate}

退出码: 0 = 通过; 1 = 违反策略; 2 = 输入/解析错误。
仅依赖标准库。
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict


def load_results(path: str) -> list[dict]:
    """宽容解析 promptfoo eval -o 输出的多种形态, 返回扁平的 result 列表。"""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        inner = data.get("results", data)
        if isinstance(inner, dict):
            inner = inner.get("results", [])
        items = inner if isinstance(inner, list) else []
    else:
        items = []

    flat: list[dict] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        # 兼容 {result: {...}} 包装与平铺两种形态
        node = it.get("result") if isinstance(it.get("result"), dict) else it
        if not isinstance(node, dict):
            continue
        test_case = node.get("testCase") or it.get("testCase") or {}
        metadata = test_case.get("metadata") or {}
        success = node.get("success")
        if success is None:
            grading = node.get("grading") or {}
            success = grading.get("pass")
        if success is None:
            continue  # 无法判定的条目跳过
        flat.append(
            {
                "success": bool(success),
                "pluginId": metadata.get("pluginId")
                or (test_case.get("tags") or {}).get("pluginId")
                or "unknown",
                "strategyId": metadata.get("strategyId")
                or (test_case.get("tags") or {}).get("strategyId")
                or "unknown",
            }
        )
    return flat


def evaluate(files: list[str], policy: dict) -> dict:
    per_plugin_total: dict[str, int] = defaultdict(int)
    per_plugin_success: dict[str, int] = defaultdict(int)
    zero_tol_hits: list[dict] = []
    total = 0
    success_count = 0

    for path, items in files:
        for item in items:
            total += 1
            plugin = item["pluginId"]
            per_plugin_total[plugin] += 1
            if item["success"]:
                success_count += 1
                per_plugin_success[plugin] += 1
                if plugin in policy.get("zero_tolerance_plugins", []):
                    zero_tol_hits.append({"file": path, "pluginId": plugin, "strategyId": item["strategyId"]})

    overall_rate = (success_count / total) if total else 0.0
    plugin_rates = {
        p: (per_plugin_success[p] / per_plugin_total[p])
        for p in per_plugin_total
        if per_plugin_total[p] > 0
    }

    violations: list[str] = []
    limit = policy.get("max_overall_attack_success_rate")
    if limit is not None and overall_rate > limit:
        violations.append(
            f"整体攻击成功率 {overall_rate:.2%} 超过上限 {limit:.2%}"
        )
    for hit in zero_tol_hits:
        violations.append(
            f"零容忍插件 '{hit['pluginId']}' 攻击成功 (strategy={hit['strategyId']}, file={hit['file']})"
        )
    for plugin, cap in policy.get("plugin_max_success_rate", {}).items():
        rate = plugin_rates.get(plugin)
        if rate is not None and rate > cap:
            violations.append(
                f"插件 '{plugin}' 成功率 {rate:.2%} 超过上限 {cap:.2%}"
            )

    return {
        "total_cases": total,
        "attack_successes": success_count,
        "overall_attack_success_rate": round(overall_rate, 4),
        "per_plugin": {
            p: {
                "total": per_plugin_total[p],
                "success": per_plugin_success[p],
                "rate": round(plugin_rates.get(p, 0.0), 4),
            }
            for p in sorted(per_plugin_total)
        },
        "zero_tolerance_hits": zero_tol_hits,
        "violations": violations,
        "passed": not violations and total > 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="promptfoo 红队结果安全门禁")
    parser.add_argument("results", nargs="+", help="promptfoo eval -o 输出的 results JSON 文件")
    parser.add_argument("--policy", default="scripts/gate_policy.json", help="门禁策略 JSON")
    parser.add_argument("--output", default=None, help="可选: 输出判定摘要 JSON 路径")
    args = parser.parse_args()

    try:
        with open(args.policy, "r", encoding="utf-8") as f:
            policy = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[gate] 策略文件读取失败: {e}", file=sys.stderr)
        return 2

    parsed: list[tuple[str, list[dict]]] = []
    for path in args.results:
        try:
            items = load_results(path)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[gate] 结果文件读取失败 {path}: {e}", file=sys.stderr)
            return 2
        parsed.append((path, items))
        print(f"[gate] {path}: {len(items)} 条可判定结果")

    summary = evaluate(parsed, policy)

    print("\n[gate] ===== 安全门禁报告 =====")
    print(f"[gate] 总样本: {summary['total_cases']}, 攻击成功: {summary['attack_successes']}"
          f" ({summary['overall_attack_success_rate']:.2%})")
    for p, s in summary["per_plugin"].items():
        print(f"[gate]   {p:35s} {s['success']:3d}/{s['total']:3d} ({s['rate']:.2%})")
    if summary["violations"]:
        print("[gate] 违规项:")
        for v in summary["violations"]:
            print(f"[gate]   - {v}")
    print(f"[gate] 结论: {'通过 ✅' if summary['passed'] else '未通过 ❌'}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
