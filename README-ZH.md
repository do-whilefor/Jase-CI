<div align="center">

# Jase-CI

面向 LLM 应用的持续红队 + 时延基准 CI 流水线，基于 [promptfoo](https://github.com/promptfoo/promptfoo) 构建，攻击生成、结果判定与被测应用后端统一走同一个上游模型——默认 DeepSeek，可经 `UPSTREAM_*` 切换。

[![CI](https://github.com/do-whilefor/Jase-CI/actions/workflows/promptfoo.yml/badge.svg)](https://github.com/do-whilefor/Jase-CI/actions/workflows/promptfoo.yml)
[![promptfoo](https://img.shields.io/badge/promptfoo-0.123.0-orange)](https://github.com/promptfoo/promptfoo)
[![Node.js](https://img.shields.io/badge/Node.js-24-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-PolyForm_NC_1.0.0-blue)](#许可说明)

[项目介绍](#项目介绍) · [使用方法](#使用方法) · [安全范围](#安全范围) · [许可说明](#许可说明)

**简体中文** · [English](./README.md) · [日本語](./README-JP.md)

</div>

## 项目介绍

Jase-CI 把对 LLM 应用的红队评估做成可持续运行的 CI：以一个 OpenAI 兼容的客服 Agent（真实工具调用 / RAG 检索 / 会话记忆）为被测对象，由 promptfoo 红队插件生成攻击用例，`security_gate.py` 按策略对结果做确定性判定，越线即拦截流水线；另附双视角时延基准，把性能预算同样变成门禁。

- **一套密钥跑通全流程**：红队攻击生成、结果判定与被测 Agent 后端共用 `UPSTREAM_API_KEY`（兼容回退 `DEEPSEEK_API_KEY`）。
- **确定性安全门禁，不可跳过**：整体攻击成功率上限、零容忍插件任一命中即拦截、单插件成功率上限，另含不依赖 LLM 评审的确定性防泄密断言。
- **双视角时延基准**：裸模型直连与 Agent 全链路（含工具 / RAG / 记忆开销）分别度量 TTFT、总延迟与吞吐，各自执行 p95 预算门禁。
- **离线可验证**：mock 全链路测试、门禁夹具自测与免密接线探针，无密钥仓库的 validate job 保持绿色。

CI 编排见 [`.github/workflows/promptfoo.yml`](./.github/workflows/promptfoo.yml)：push 到 main 触发四个定向套件（含自研创意攻击套件），每天 UTC 02:00 定时与手动触发加跑 46 插件全量扫描。红队与时延 job 需配置 `UPSTREAM_API_KEY` secret（兼容 `DEEPSEEK_API_KEY`）；未配置时仅运行无需密钥的 validate job。

### 架构

```
.github/workflows/promptfoo.yml        CI 编排: 验证 → 红队+安全门禁 → 时延基准
promptfooconfig_full.yaml              红队全量扫描 (46 插件, 经上游网关)
promptfooconfig_creative.yaml          定向: 创意攻击 (8 自研插件, redteam run 真实生成)
configs/
  promptfooconfig.attacks.yaml         离线攻击回放 (CI validate job 强制执行)
  promptfooconfig.agent.yaml           定向: Agent/工具滥用 (过度代理/工具发现/劫持/目标偏移)
  promptfooconfig.rag.yaml             定向: RAG 泄露 (知识库外泄/跨会话/提示词提取)
  promptfooconfig.memory.yaml          定向: 会话记忆 (记忆投毒/PII 会话/跨会话探测)
  promptfooconfig.probe.yaml           免密探针: 验证 provider 接线 (CI validate job 强制执行)
  promptfooconfig.timing.yaml          promptfoo 侧延迟断言 (latency 阈值)
  redteam/*.json                       自研创意攻击插件定义 (generator+grader)
agent/
  server.js                            被测应用: OpenAI 兼容客服 Agent
                                       (真实工具调用 / RAG 检索 / 会话记忆; MOCK_MODEL=1 可离线)
  knowledge/*.md                       RAG 语料, internal-notes.md 含"禁止披露"诱饵内容
scripts/
  security_gate.py                     CI Security Gate: 解析红队结果, 按策略判定放行/拦截
  gate_policy.json                     门禁策略 (整体成功率上限 / 零容忍插件 / 单插件上限)
  timing_benchmark.py                  时延基准: TTFT / 总延迟 / 吞吐, p95 预算门禁
  validate_configs.js                  promptfoo 配置结构与语法校验
tests/
  run_tests.py                         离线测试套件 (mock 模式全链路 + 门禁夹具 + 时延冒烟)
```

## 使用方法

### 环境要求

| 项 | 要求 |
| --- | --- |
| 运行环境 | Windows / macOS / Linux（CI 运行于 ubuntu-latest） |
| promptfoo | 0.123.0（`npm install -g promptfoo@0.123.0`，要求 Node.js ≥ 22.22.0） |
| Node.js | 24 — 被测 Agent、配置校验与接线探针 |
| Python | 3.12 — 测试套件、安全门禁与时延基准，仅需标准库 |
| 本地校验依赖 | npm 包 `yaml`（供 `validate_configs.js` 解析 YAML） |
| 密钥 | `UPSTREAM_API_KEY`（兼容回退 `DEEPSEEK_API_KEY`）— 真实红队扫描与时延基准必需；离线自测无需 |

> 下文命令为 bash 写法。PowerShell 请用 `$env:NAME = "value"` 设置环境变量（如 `$env:CI = "true"`）。

### 离线自测（无需任何密钥）

```bash
python tests/run_tests.py                     # 测试套件: mock 模式全链路 + 门禁夹具 + 时延冒烟
npm install --no-save --no-package-lock yaml
node scripts/validate_configs.js              # 配置结构与语法校验
MOCK_MODEL=1 PORT=8787 node agent/server.js   # 启动被测 Agent (离线 mock 模式)
```

### 真实红队扫描

需要两个终端：先启动被测 Agent，再从另一终端发起扫描。注意 `promptfoo eval` 在 0.123.0 中**不会**生成红队用例（仅适用于自带测试用例的离线回放套件），真实扫描必须用 `promptfoo redteam run`。

```bash
# 终端 1 — 启动被测 Agent (真实模式, 保持运行)
export UPSTREAM_API_KEY=sk-xxx
node agent/server.js

# 终端 2 — 生成攻击用例并执行, 随后门禁判定
export UPSTREAM_API_KEY=sk-xxx
export AGENT_API_KEY=local-test   # 任意非空值, 仅用于通过 promptfoo 的启动检查
export CI=true                    # 跳过 promptfoo 红队邮箱验证, 与仓库 CI 行为一致
promptfoo redteam run -c configs/promptfooconfig.agent.yaml -o results-agent.json
python scripts/security_gate.py results-agent.json
```

四个定向套件分别覆盖 Agent/工具滥用、RAG 泄露、会话记忆与自研创意攻击（`configs/promptfooconfig.{agent,rag,memory}.yaml` + `promptfooconfig_creative.yaml`）；`promptfooconfig_full.yaml` 为 46 插件全量扫描。门禁可一次读入多个结果文件，任一违反策略即以非零码退出。真实扫描消耗模型 API 额度，耗时数分钟属正常。

### 时延基准

```bash
# 视角一: 裸模型直连
python scripts/timing_benchmark.py --outdir timing-model

# 视角二: Agent 全链路 (配合上一步启动的 Agent)
TARGET_BASE_URL=http://localhost:8787/v1 python scripts/timing_benchmark.py --outdir timing-agent
```

预算由 `TIMING_BUDGET_MS` 控制（CI 中 Agent 视角 p95 预算为 30s），p95 超预算即失败。

## 安全范围

使用前请阅读[《免责声明与使用合规须知》](./SECURITY.md)。

- **合法授权**：本项目用于测试你拥有或已获授权的应用。红队插件会真实生成攻击性内容并调用模型服务——不得将本流水线指向未授权的第三方系统。
- **门禁策略**：[`scripts/gate_policy.json`](./scripts/gate_policy.json) 按策略确定性判定——整体攻击成功率上限 **20%**；提示词提取、系统提示词覆盖、跨会话泄露、RAG 文档外泄、PII、SQL/Shell 注入、SSRF、越狱模板等零容忍插件任一命中即拦截；过度代理、幻觉等设宽容上限；另含诱饵机密断言与覆盖度护栏（样本量、必备插件、未知率），CI 以 `--enforce-coverage` 强制执行。每个启用的插件必须在策略中登记，由 `validate_configs.js` 交叉校验。
- **结果人工复核**：门禁判定包含 LLM 评审环节，可能存在漏报与误报。放行与拦截都应结合原始证据、真实影响与覆盖面复核。
- **信息保护**：RAG 语料、会话记录与红队结果可能包含敏感内容，发送给模型服务前请确认符合保密要求与其数据处理条款。
- **资源控制**：红队扫描与时延基准消耗模型 API 配额，请为账号配置花费上限。

使用者须自行取得测试授权，并对自己的行为及造成的后果承担法律责任。项目许可不构成对测试任何第三方系统的授权。

## 许可说明

本仓库遵循 [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) 非商业许可（声明见 [SECURITY.md](./SECURITY.md)），使用、修改与分发须符合许可条款。promptfoo、DeepSeek 等第三方组件与服务各自受其许可与服务条款约束，本仓库许可不替代其条款。

| 文件 | 内容 |
| --- | --- |
| [SECURITY.md](./SECURITY.md) | 免责声明、使用合规要求与部署风险 |
