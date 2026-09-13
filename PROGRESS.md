# pf-ci-timing 进度看板

> 更新时间: 2026-09-13

| 能力项 | 完成度 | 状态与说明 |
|---|---|---|
| Promptfoo 配置 | 100% | 5 个定向/探针配置 + 全量配置, 结构校验通过; 插件 ID 与 provider target 写法均经 promptfoo@0.123.0 真实运行时验证 |
| DeepSeek 接入 | 100% | 攻击生成/判定/Agent 后端统一走 DeepSeek, 全部经 `apiKeyEnvar` 注入, 无内联 key |
| GitHub Actions | 100% | 三 job 编排; 首次 CI 失败根因 (validate_configs 加载不到 yaml) 已修复并本地复现验证; validate 含接线探针 |
| 真正 RedTeam 执行 | 95% | 定向套件 target 为经验证的 `openai:chat + apiBaseUrl` 写法; 增加确定性防泄密断言; 配置 secret 后即可真实执行 |
| CI Security Gate | 95% | 策略判定 + 确定性断言双保险; 报告含插件/攻击策略双维度成功率 |
| App / Agent 测试 | 95% | 被测 Agent 上线(真实工具执行)且 provider 接线端到端探针通过, `agent` 套件覆盖过度代理/工具发现/劫持/目标偏移/间接注入 |
| RAG 真实测试 | 95% | Agent 真实检索 `knowledge/*.md`(含禁披露诱饵文件), provider 接线已探针验证, `rag` 套件覆盖文档外泄/跨会话/提取 |
| Tool 真实测试 | 95% | 4 个真实工具(订单/退款/搜索/客户资料), 退款无确认环节作为过度代理真实命中面, provider 接线已探针验证 |
| Memory 真实测试 | 90% | Agent 按 `X-Session-Id` 持久化多轮历史且会话隔离; 探针证实 `config.headers` 会话头真实送达 agent; `memory` 套件覆盖投毒/PII 会话/跨会话探测 |
| Timing Benchmark | 95% | 双视角基准 (裸模型 vs Agent 全链路), 各自 p95 预算门禁 + promptfoo `latency` 断言; mock 冒烟通过, 真实数据待 CI 首跑 |

## 剩余事项 (需要仓库操作权限或首次 CI 运行)

1. 在 GitHub 仓库 Settings → Secrets 配置 `DEEPSEEK_API_KEY`, 红队与时延 job 才会实际执行。
2. 手动触发一次 workflow_dispatch, 确认三个 job 全绿、产物上传完整。
3. 依据首次真实扫描结果调优 `gate_policy.json` 阈值(当前为初版基线)。
