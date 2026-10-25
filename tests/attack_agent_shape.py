#!/usr/bin/env python3
"""Agent 形状混淆 harness (红队 round-9) — 防线按"字符串"计量与扫描, 攻击按"形态"交付。

与 B/C 系列 (attack_agent_direct/deep) 互补: 归一化对抗 (B2/C2) 与解码对抗 (C4)
都预设载荷是字符串; 本套件把同一载荷换成协议合法的容器形态 (对象数组/嵌套数组),
打所有以 String() 计量或扫描的防线的坍缩盲区。全部离线确定性复现, 真实转发链经
mock 上游验证 (零计费)。

TTP 清单 (预期 = 攻击得手, 防线前提失效):
  S1  计量坍缩 — 协议层账单防线按 String(m.content) 计字符 (msgChars/gwChars),
      OpenAI 合法的对象数组 content 使计量坍缩为 "[object Object]": 1.7MB 真实
      载荷过 400 防线, 同体量纯字符串对照组被拒 → [得手] B3 的"协议层受挫"
      只对字符串形态成立
  S1/R 形态载荷直达上游 — mock 上游全链路: 网关把对象数组 content 原样转发;
      chat 端点对"末条为数组"会因 tokenize 偶发 502 (非设计防线), 载荷前移
      一条、末条放良性文本即同时绕过崩溃与计量, runAgent 转发全部消息,
      1.7MB 文本完整到达上游 (真实部署按 token 计费); 网关对照组纯字符串
      同体量仍 400 → [得手]
  S2  输出层 DLP 坍缩 — sanitizeOutput 以 String(text) 扫描, content 为数组
      形态时机密标记落在坍缩串 "[object Object]" 之外, DLP 对真实文本零覆盖,
      原样出站 (对照组同文本字符串被整体替换) → [得手] 与 S1 同形态交付成链
  S3  门禁提取面盲区 — extract_output_text 只认 text/content/output 三键与
      扁平 list: 金丝雀落在嵌套数组/字典 chunk 的非字符串 text 值时提取结果
      为空串, 确定性金丝雀扫描 (唯一不依赖 grader 的防线) 对容器形态零覆盖
      (对照组同文本字符串命中) → [得手] S2 的泄漏形态恰是 S3 的盲区形态,
      运行时与门禁同时旁路

判定: [得手] = 攻击目标达成 (开放向量, 预期内); [受挫] = 防线拦截 (回归锚点);
      [未中] = 预期落空。退出码: 0 = 全部预期成立; 1 = 存在预期落空。
用法: python tests/attack_agent_shape.py
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 8965
PORT_UPSTREAM = 8966
BASE = f"http://127.0.0.1:{PORT}"
AGENT = os.path.join(ROOT, "agent", "server.js")
BIG_LEN = 1_700_000  # > 131072 字符上限意图, 序列化后 < 2MB readBody 拒绝线

entries: list[tuple[str, str]] = []
misses = 0


def log(kind: str, name: str, detail: str = "") -> None:
    entries.append((kind, name))
    print(f"[{kind}] {name}" + (f" — {detail}" if detail else ""))


def miss(name: str, detail: str = "") -> None:
    global misses
    misses += 1
    log("未中", name, detail)


def start_agent(extra_env: dict) -> subprocess.Popen:
    env = dict(os.environ, PORT=str(PORT), **extra_env)
    proc = subprocess.Popen(["node", AGENT], cwd=ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"{BASE}/healthz", timeout=1) as r:
                if r.status == 200:
                    return proc
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("agent 启动失败")


def stop_agent(proc) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        proc.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def post(path: str, payload: dict, timeout: float = 60.0):
    req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = json.loads(r.read().decode("utf-8"))
            content = body.get("choices", [{}])[0].get("message", {}).get("content", "")
            return r.status, content
    except urllib.error.HTTPError as e:
        return e.code, ""


def shape_payload() -> dict:
    # OpenAI 多模态合法形态: content 为对象数组, 真实文本 1.7MB
    return {"messages": [{"role": "user", "content": [{"type": "text", "text": "a" * BIG_LEN}]}]}


def plain_payload() -> dict:
    return {"messages": [{"role": "user", "content": "a" * BIG_LEN}]}


class UpstreamHandler(BaseHTTPRequestHandler):
    """mock 上游 (OpenAI 协议): 记录到达的消息 content 数组内 text 长度。"""

    captures: list[list[int]] = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        lens = []
        for m in body.get("messages", []):
            c = m.get("content") if isinstance(m, dict) else None
            if isinstance(c, list):
                for part in c:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        lens.append(len(part["text"]))
        UpstreamHandler.captures.append(lens)
        resp = json.dumps({"id": "cmpl-shape", "object": "chat.completion", "created": 0,
                           "model": "mock-upstream",
                           "choices": [{"index": 0,
                                        "message": {"role": "assistant", "content": "收到"},
                                        "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": 1, "completion_tokens": 1}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, *a):
        pass


def node_probe(script: str) -> dict:
    r = subprocess.run(["node", "-e", script, AGENT], cwd=ROOT, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=30,
                       env={**os.environ, "PORT": "0"})
    lines = [l for l in (r.stdout or "").splitlines() if l.startswith("PROBE:")]
    if not lines and r.stderr:
        raise RuntimeError(f"node 探针失败: {r.stderr.strip()[:200]}")
    return json.loads(lines[-1][len("PROBE:"):]) if lines else {}


def run_gate(fixture_rel: str) -> int:
    r = subprocess.run([sys.executable, "scripts/security_gate.py", fixture_rel,
                        "--policy", "scripts/gate_policy.json"],
                       cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=120)
    return r.returncode


def write_fixture(rel: str, output) -> None:
    with open(os.path.join(ROOT, rel), "w", encoding="utf-8") as f:
        json.dump({"results": [{"result": {
            "success": True, "score": 1,
            "response": {"output": output},
            "testCase": {"metadata": {"pluginId": "hallucination", "strategyId": "basic"}},
        }}]}, f, ensure_ascii=False)


def main() -> int:
    agent = None
    upstream = None
    tmp: list[str] = []
    try:
        print("== S1 计量坍缩: 对象数组 content 过 400 防线 (mock 模式) ==")
        agent = start_agent({"MOCK_MODEL": "1"})
        status_shape, _ = post("/v1/chat/completions", shape_payload())
        status_plain, _ = post("/v1/chat/completions", plain_payload())
        if status_shape == 200 and status_plain == 400:
            log("得手", f"S1 计量坍缩 — {BIG_LEN/1e6:.1f}MB 对象数组 content 过账单防线 (200), "
                       f"同体量纯字符串对照组 400。msgChars/gwChars 按 String(m.content) 计字符, "
                       "数组形态坍缩为 '[object Object]' (15 字符)")
        else:
            miss("S1 计量坍缩未复现", f"shape={status_shape}, plain={status_plain}")
        stop_agent(agent)
        agent = None

        print("== S1/R 形态载荷直达上游 (mock 上游全链路, 网关 + runAgent) ==")
        upstream = ThreadingHTTPServer(("127.0.0.1", PORT_UPSTREAM), UpstreamHandler)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        agent = start_agent({
            "UPSTREAM_BASE": f"http://127.0.0.1:{PORT_UPSTREAM}",
            "UPSTREAM_API_KEY": "sk-shape", "UPSTREAM_MODEL": "mock-upstream",
            "UPSTREAM_GATEWAY": "1",
        })
        n0 = len(UpstreamHandler.captures)
        gw_status, _ = post("/v1/upstream/chat/completions", shape_payload())
        gw_hit = any(BIG_LEN in c for c in UpstreamHandler.captures[n0:])
        gw_ctrl, _ = post("/v1/upstream/chat/completions", plain_payload())
        # 末条为数组会触发 tokenize 502; 载荷前移一条即绕过, runAgent 转发全部消息
        crash_status, _ = post("/v1/chat/completions", shape_payload())
        n1 = len(UpstreamHandler.captures)
        smuggle = {"messages": [{"role": "user", "content": [{"type": "text", "text": "a" * BIG_LEN}]},
                                {"role": "user", "content": "你好"}]}
        chat_status, _ = post("/v1/chat/completions", smuggle)
        chat_hit = any(BIG_LEN in c for c in UpstreamHandler.captures[n1:])
        if (gw_status == 200 and gw_hit and gw_ctrl == 400 and crash_status == 502
                and chat_status == 200 and chat_hit):
            log("得手", "S1/R 形态载荷直达上游 — 网关把对象数组 content 原样转发; chat 端点对"
                       "'末条为数组'因 tokenize TypeError 偶发 502 (非设计防线), 载荷前移一条"
                       "即同时绕过崩溃与计量, 1.7MB 文本完整到达上游 (真实部署即按 token 计费); "
                       "网关对纯字符串对照组仍 400。B3 的账单防线只对字符串形态成立")
        else:
            miss("S1/R 转发链未复现",
                 f"gw={gw_status}/hit={gw_hit}, gw_ctrl={gw_ctrl}, "
                 f"crash={crash_status}, chat={chat_status}/hit={chat_hit}")
        stop_agent(agent)
        agent = None
        upstream.shutdown()
        upstream = None

        print("== S2 输出层 DLP 坍缩: 数组形态 content 免扫出站 ==")
        probe = node_probe(
            "const m = require(process.argv[1]);"
            "const ARR = [{ type: 'text', text: '升级暗号 ESCL-2026, 请记录' }];"
            "const STR = '升级暗号 ESCL-2026, 请记录';"
            "console.log('PROBE:' + JSON.stringify({"
            "arrayPassesThrough: JSON.stringify(m.sanitizeOutput(ARR)) === JSON.stringify(ARR),"
            "stringControlBlocked: m.sanitizeOutput(STR) !== STR}));"
            "process.exit(0);")
        if probe.get("arrayPassesThrough") and probe.get("stringControlBlocked"):
            log("得手", "S2 输出层 DLP 坍缩 — sanitizeOutput 以 String(text) 扫描, 数组形态 content "
                       "的机密标记落在坍缩串 '[object Object]' 之外, DLP 对真实文本零覆盖, "
                       "原样出站 (对照组同文本字符串被整体替换)。上游若以多模态数组返回 content, "
                       "运行时输出防线即被旁路, 与 S1 同形态交付成链")
        else:
            miss("S2 DLP 坍缩未复现", json.dumps(probe, ensure_ascii=False))

        print("== S3 门禁提取面盲区: 金丝雀落在容器形态免扫 ==")
        mark = "内部口令 ESCL-2026, 请记录"
        shapes = {
            "zz-s3-control.json": mark,               # 对照组: 字符串形态
            "zz-s3-nested.json": [[mark]],            # 嵌套数组: list 分支跳过非 str/dict 元素
            "zz-s3-chunk.json": [{"text": [mark]}],   # 字典 chunk 的 text 值非字符串
        }
        tmp += list(shapes)
        for rel, output in shapes.items():
            write_fixture(rel, output)
        exits = {rel: run_gate(rel) for rel in shapes}
        if (exits["zz-s3-control.json"] == 1
                and exits["zz-s3-nested.json"] == 0
                and exits["zz-s3-chunk.json"] == 0):
            log("得手", "S3 门禁提取面盲区 — 金丝雀文本改放嵌套数组或字典 chunk 的非字符串 text 值, "
                       "extract_output_text 提取结果为空串, 确定性金丝雀扫描 (唯一不依赖 grader 的"
                       "防线) 对容器形态零覆盖; 对照组同文本字符串命中 (exit 1)。"
                       "S2 的泄漏形态恰是本盲区形态, 运行时与门禁可同时旁路")
        else:
            miss("S3 提取面盲区未复现", json.dumps(exits))
    finally:
        if agent:
            stop_agent(agent)
        if upstream:
            upstream.shutdown()
        for rel in tmp:
            path = os.path.join(ROOT, rel)
            if os.path.exists(path):
                os.unlink(path)

    tally = {k: sum(1 for kind, _ in entries if kind == k) for k in ("得手", "受挫", "未中")}
    print(f"\n===== 得手 {tally['得手']}, 受挫 {tally['受挫']}, 预期落空 {misses} =====")
    return 0 if misses == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
