# pf-ci-timing 进度看板

> 更新时间: 2026-09-13

| 能力项 | 完成度 | 状态与说明 |
|---|---|---|
| Promptfoo 配置 | 100% | 4 个定向配置 + 全量配置, 全部通过结构校验; 插件 ID 已逐一对 promptfoo@0.123.0 核验 |
| DeepSeek 接入 | 100% | 攻击生成/判定/Agent 后端统一走 DeepSeek, 全部经 `apiKeyEnvar` 注入, 无内联 key |
| GitHub Actions | 100% | 三 job 编排: validate(免密) → redteam+gate → timing; push/schedule/dispatch 三种触发 |
| 真正 RedTeam 执行 | 95% | 原工作流的 `--dry-run` 冒烟是无效参数(被 `\|\| true` 掩盖); 现已修正并接线; 配置 secret 后即可真实执行 |
| CI Security Gate | 90% | `security_gate.py` + `gate_policy.json`(整体20%/零容忍/单插件上限), 夹具自测 0/1 退出码均验证通过 |
| App / Agent 测试 | 90% | 被测 Agent 上线(真实工具执行), `agent` 套件覆盖过度代理/工具发现/劫持/目标偏移/间接注入 |
| RAG 真实测试 | 90% | Agent 真实检索 `knowledge/*.md`(含禁披露诱饵文件), `rag` 套件覆盖文档外泄/跨会话/提取 |
| Tool 真实测试 | 90% | 4 个真实工具(订单/退款/搜索/客户资料), 退款无确认环节作为过度代理真实命中面 |
| Memory 真实测试 | 85% | Agent 按 `X-Session-Id` 持久化多轮历史且会话隔离, `memory` 套件覆盖投毒/PII 会话/跨会话探测 |
| Timing Benchmark | 90% | `timing_benchmark.py`(TTFT/总延迟/吞吐, p95 预算门禁) + promptfoo `latency` 断言; mock 冒烟通过, 真实数据待 CI 首跑 |

## 剩余事项 (需要仓库操作权限或首次 CI 运行)

1. 在 GitHub 仓库 Settings → Secrets 配置 `DEEPSEEK_API_KEY`, 红队与时延 job 才会实际执行。
2. 手动触发一次 workflow_dispatch, 确认三个 job 全绿、产物上传完整。
3. 依据首次真实扫描结果调优 `gate_policy.json` 阈值(当前为初版基线)。
