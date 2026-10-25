#!/usr/bin/env python3
"""门禁 property-based fuzzer — 随机生成对抗结果文件, 断言 fail-closed 不变量。

与手造探针 (probe_gate_adversarial.py) 互补: 探针覆盖已知向量, fuzzer 用
随机组合 (编码变换 × 结果形态 × 判定类型 × 诱饵噪声) 找第 17 类解析洞。

不变量:
  I1 不崩溃    — 任何构造输入下 load_results/evaluate 除预期 ValueError 外不抛异常
  I2 必检      — 标记经门禁已声称覆盖的变换 (明文/rot13/base64/base64url/hex/base32/
                 空白分段/零宽/NBSP替空格/全角/leet映射/双层组合/字符间NBSP/MVS/
                 变体选择符/UnicodeTags/同形字, 含诱饵 token) 后,
                 evaluate 必须判违规 (passed=False)
  I3 退出码    — 子进程抽检: 必检样本退出码必须为 1, 且任何退出码 ∈ {0,1,2}
  I4 严格解析  — 非布尔判定 / NaN / Infinity / 重复键必须被拒绝 (ValueError)

变换分两类: handled (门禁已声称覆盖, 漏检即 I2 违例) 与 evasive (已知剩余边界,
仅统计命中情况 — 组合附加符号/未收录同形字/三层编码+诱饵)。

配置 (环境变量): FUZZ_N=400, FUZZ_SEED=20261025, FUZZ_SUBSAMPLE=40
发现违例时保存复现夹具到 tests/fixtures/adversarial-fuzz/ 并退出 1; 全部通过退出 0。
用法: python tests/fuzz_gate.py
"""
from __future__ import annotations

import base64
import codecs
import importlib.util
import itertools
import json
import os
import random
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOLEDIFF = os.path.join(ROOT, "tests", "fixtures", "adversarial-fuzz")

N = int(os.environ.get("FUZZ_N", "400"))
SEED = int(os.environ.get("FUZZ_SEED", "20261025"))
SUBSAMPLE = int(os.environ.get("FUZZ_SUBSAMPLE", "40"))

with open(os.path.join(ROOT, "scripts", "gate_policy.json"), encoding="utf-8") as f:
    POLICY = json.load(f)
MARKERS = POLICY["forbidden_output_markers"]
VOCAB = (POLICY["required_plugins"] + POLICY["zero_tolerance_plugins"]
         + list(POLICY["plugin_max_success_rate"]))

_spec = importlib.util.spec_from_file_location(
    "security_gate", os.path.join(ROOT, "scripts", "security_gate.py"))
GATE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(GATE)


def _leet_attack(s: str) -> str:
    return s.translate(str.maketrans("eaotisb" + "EAOTISB", "3407158" * 2))


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _hex(s: str) -> str:
    return s.encode().hex()


def _b32(s: str) -> str:
    return base64.b32encode(s.encode()).decode()


def _rot13(s: str) -> str:
    return codecs.encode(s, "rot13")


_STR_ENCODERS = [("rot13", _rot13), ("b64", _b64), ("hex", _hex), ("b32", _b32)]


def _ws_split(s: str) -> str:
    tok = _b64(s)
    return " ".join(tok[i:i + 8] for i in range(0, len(tok), 8))


def _fullwidth(s: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if 33 <= ord(c) <= 126 else c for c in s)


def _compose(a, b):
    return lambda s: a(b(s))


HANDLED = [
    ("明文", lambda s: s),
    ("rot13", _rot13),
    ("base64", _b64),
    ("base64url", lambda s: base64.urlsafe_b64encode(s.encode()).decode()),
    ("hex小写", _hex),
    ("hex大写", lambda s: _hex(s).upper()),
    ("base32", _b32),
    ("b64空白分段", _ws_split),
    ("零宽插入", lambda s: "\u200b".join(s)),
    ("NBSP替空格", lambda s: s.replace(" ", "\u00a0")),
    ("全角", _fullwidth),
    ("leet映射", _leet_attack),
    ("未映射leet(6→b)", lambda s: s.replace("6", "b")),
    ("字符间NBSP", lambda s: "\u00a0".join(s)),
    ("字符间MVS", lambda s: "\u180e".join(s)),
    ("变体选择符", lambda s: "\ufe0f".join(s)),
    ("变体选择符增补", lambda s: "\U000E0100".join(s)),
    ("UnicodeTags", lambda s: "".join(chr(0xE0000 + ord(c)) for c in s)),
    ("同形字", lambda s: s.translate(str.maketrans(
        {"E": "\u0415", "S": "\u0405", "C": "\u0421", "A": "\u0410", "O": "\u041E",
         "T": "\u0422", "B": "\u0412", "P": "\u0420", "K": "\u041A", "M": "\u041C",
         "H": "\u041D", "X": "\u0425", "a": "\u0430", "e": "\u0435", "o": "\u043E",
         "c": "\u0441", "p": "\u0440", "y": "\u0443", "x": "\u0445"}))),
] + [(f"双层{a}∘{b}", _compose(fa, fb)) for (a, fa), (b, fb)
     in itertools.product(_STR_ENCODERS, repeat=2)]

EVASIVE = [
    ("组合附加符号", lambda s: "\u0301".join(s)),
    ("未收录同形字(Ƅ)", lambda s: s.replace("B", "\u0184")),
    ("三层编码+诱饵", lambda s: " ".join(
        [_rot13(_b64(_rot13(s)))]
        + [_b64(f"decoy-{i:03d}") for i in range(300)])),
]

PREFIXES = ["核验结果:", "归档记录", "", "备注", "已同步:"]
SUFFIXES = ["已归档", "", "(内部备注)", "完毕", "请查收"]


def make_case(rng: random.Random):
    """返回 (类别, 变换名, 标记, results 文档 dict)。"""
    for _ in range(64):
        marker = rng.choice(MARKERS)
        klass = "must" if rng.random() < 0.65 else "evade"
        name, fn = rng.choice(HANDLED if klass == "must" else EVASIVE)
        payload = fn(marker)
        if payload == marker or marker in payload:
            continue  # 变换未生效 (如对纯中文做 rot13), 重采样
        text = f"{rng.choice(PREFIXES)} {payload} {rng.choice(SUFFIXES)}".strip()
        if klass == "must" and rng.random() < 0.4:
            text += " " + " ".join(
                _b64(f"benign-{i:03d}") for i in range(rng.randint(1, 20)))
        node = {"success": True, "score": 1,
                "testCase": {"metadata": {
                    "pluginId": rng.choice(VOCAB),
                    "strategyId": rng.choice(["basic", "rot13", "layer", "jailbreak-templates"])}}}
        node["response"] = {"output": text}
        item = {"result": node} if rng.random() < 0.5 else node
        doc = rng.choice([{"results": {"results": [item]}}, {"results": [item]}, [item]])
        return klass, name, marker, doc
    raise AssertionError("64 次重采样未生成有效用例")


def make_malformed(kind: str):
    """I4 类: 必须被严格解析拒绝的判定形态。"""
    base_node = {"testCase": {"metadata": {"pluginId": "prompt-extraction",
                                           "strategyId": "basic"}}}
    if kind == "字符串success":
        base_node = {"success": "false", **base_node}
        return {"results": {"results": [{"result": base_node}]}}
    if kind == "字符串grading":
        return {"results": {"results": [{"result": {**base_node, "grading": {"pass": "false"}}}]}}
    if kind == "NaN":
        base_node = {"success": float("nan"), **base_node}
        return {"results": {"results": [{"result": base_node}]}}
    if kind == "Infinity":
        base_node = {"success": float("inf"), **base_node}
        return {"results": {"results": [{"result": base_node}]}}
    if kind == "重复键":
        return ('{ "results": { "results": [ { "result": { "success": false,'
                ' "success": true, "testCase": {} } } ] } }')
    raise AssertionError(kind)


def write_doc(doc, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        if isinstance(doc, str):
            f.write(doc)
        else:
            json.dump(doc, f, ensure_ascii=False)


def save_hole(doc, filename: str) -> None:
    os.makedirs(HOLEDIFF, exist_ok=True)
    write_doc(doc, os.path.join(HOLEDIFF, filename))


def main() -> int:
    rng = random.Random(SEED)
    holes: list[str] = []
    evade_stats: dict[str, list[int]] = {}
    must_total = 0
    subprocess_samples: list[tuple[dict, bool]] = []

    with tempfile.TemporaryDirectory() as td:
        for i in range(N):
            klass, name, marker, doc = make_case(rng)
            path = os.path.join(td, f"case-{i:04d}.json")
            write_doc(doc, path)
            try:
                items = GATE.load_results(path)
                summary = GATE.evaluate([(path, items)], POLICY, enforce_coverage=False)
            except ValueError:
                holes.append(f"I2/I1: 必检样本被严格解析拒绝 (klass={klass}, 变换={name}, 标记={marker})")
                save_hole(doc, f"i2-reject-{i:04d}.json")
                continue
            except Exception as e:  # I1: 任何其他异常都是崩溃
                holes.append(f"I1 崩溃: {type(e).__name__}: {e} (变换={name}, 标记={marker})")
                save_hole(doc, f"i1-crash-{i:04d}.json")
                continue

            if klass == "must":
                must_total += 1
                if summary["passed"]:
                    holes.append(f"I2 漏检: 变换={name}, 标记={marker} — 门禁放行含标记输出")
                    save_hole(doc, f"i2-miss-{i:04d}.json")
                elif not any("金丝雀" in v for v in summary["violations"]):
                    holes.append(f"I2 异因拦截: 变换={name}, 标记={marker} — 拦截但非金丝雀原因"
                                 f" ({summary['violations']})")
                if len(subprocess_samples) < SUBSAMPLE:
                    subprocess_samples.append((doc, True))
            else:
                stat = evade_stats.setdefault(name, [0, 0])
                stat[1] += 1
                if not summary["passed"]:
                    stat[0] += 1  # 被检出 (好)

        # I4: 严格解析类
        for kind in ("字符串success", "字符串grading", "NaN", "Infinity", "重复键"):
            doc = make_malformed(kind)
            path = os.path.join(td, f"mal-{kind}.json")
            write_doc(doc, path)
            try:
                GATE.load_results(path)
                holes.append(f"I4 未拒绝: {kind} 形态被宽容接受")
                save_hole(doc, f"i4-{kind}.json")
            except ValueError:
                pass
            except Exception as e:
                holes.append(f"I1 崩溃 (I4 类 {kind}): {type(e).__name__}: {e}")

        # I3: 子进程抽检 — 必检样本退出码必须为 1, 且 ∈ {0,1,2}
        for j, (doc, is_must) in enumerate(subprocess_samples):
            path = os.path.join(td, f"sub-{j:03d}.json")
            write_doc(doc, path)
            r = subprocess.run(
                [sys.executable, os.path.join("scripts", "security_gate.py"), path,
                 "--policy", os.path.join("scripts", "gate_policy.json")],
                cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=60,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"})
            if r.returncode not in (0, 1, 2):
                holes.append(f"I3 退出码越界: {r.returncode} (样本 {j})")
                save_hole(doc, f"i3-rc-{j:03d}.json")
            elif is_must and r.returncode != 1:
                holes.append(f"I3 必检样本退出码 {r.returncode} != 1 (样本 {j})")
                save_hole(doc, f"i3-miss-{j:03d}.json")

    print(f"== 门禁 fuzzer ==  种子 {SEED}, 用例 {N} (必检 {must_total}, 逃逸类 {N - must_total - 5}),"
          f" 子进程抽检 {len(subprocess_samples)}, 严格解析 5 类")
    for name, (detected, total) in sorted(evade_stats.items()):
        print(f"  [逃逸类] {name:14s} 检出 {detected}/{total}"
              + (" (已被门禁覆盖, 可移入必检)" if detected == total else ""))
    if holes:
        print(f"\n===== 发现 {len(holes)} 个违例 =====")
        for h in holes:
            print(f"  ✗ {h}")
        print(f"复现夹具: {os.path.relpath(HOLEDIFF, ROOT)}/")
        return 1
    print(f"\n===== 不变量全部成立: I1 不崩溃 / I2 必检 {must_total}/{must_total} /"
          f" I3 退出码 / I4 严格解析 =====")
    return 0


if __name__ == "__main__":
    sys.exit(main())
