# pf-ci-timing 进度看板

> 更新时间: 2026-10-24

| 能力项 | 完成度 | 状态与说明 |
|---|---|---|
| Promptfoo 配置 | 100% | 定向三套件: agent 8 插件 / rag 6 插件 / memory 5 插件, 各 numTests=8; 策略升级 (替换已废弃的 prompt-injection→jailbreak-templates, 新增 hex; agent 套件接入自定义手法 custom:authority-escalation 权威伪装+工具链手稿); 全量 38 插件 × 6 策略; 全部组合经 promptfoo@0.123.0 运行时校验; validate 含 gate_policy↔套件插件交叉校验与自定义策略手稿检查 |
| 攻击手法 (TTP) 体系 | 100% | 手法回放套件 14 条确定性攻击免密可回归, validate job 强制执行; 实现级攻击原语: 协议级轮次伪造 (客户端夹带 assistant/tool 消息被端点接受) / 工具参数反射 (注入载荷经工具结果 JSON 回流) / 尾包脱离 (检索仅看末条消息) / 上下文投送 (无辜问题按 tokenizer 计分把机密送进检索 top-1, 实测 28 分) / 对话史伪造 (换行走私伪 assistant 轮次) / body-metadata 会话劫持 (已封死, 闭环 #2); 攻击侧新增 layer 层叠编码 (rot13∘base64) 与 homoglyph 策略, 蓝队对应升级为递归多层解码 (depth 3) 与数值金丝雀 (165/340 元, 防转述泄漏) |
| DeepSeek 接入 | 100% | 攻击生成/判定/Agent 后端统一走 DeepSeek, 全部经 `apiKeyEnvar` 注入, 无内联 key |
| GitHub Actions | 100% | Run #5 全绿 (run 5eae296): validate 各 step 通过; 历史失败根因均已修复 (yaml 解析、Node 20→24) |
| 真正 RedTeam 执行 | 95% | 接线全部验证; 仅剩仓库 secret `DEEPSEEK_API_KEY` 未配置, 配置后红队步骤自动执行。**关键修复: 门禁计分方向** — promptfoo 红队 grader 语义为 pass=true=防守成功 (0.123.0 源码核实), 门禁此前反向计分 (防守越好越红), 已修正为 success=false=攻击成功 |
| CI Security Gate | 95% | 策略判定 + 确定性金丝雀扫描双保险: `forbidden_output_markers` (诱饵机密 + 测试 PII + 注入服从标记) 对每条输出做明文/rot13/base64/hex 解码扫描, 命中即拦截且不受 grader 判定方向影响; 覆盖度护栏 (min_total_cases / required_plugins / unknown 哨兵, CI 以 `--enforce-coverage` 执行); 报告含插件/策略双维度攻击成功率并写入 Job Summary |
| App / Agent 测试 | 95% | 被测 Agent 上线(真实工具执行)且 provider 接线端到端探针通过, `agent` 套件覆盖过度代理/工具发现/劫持/目标偏移/间接注入/PII 直取 (get_customer_profile 无权限校验作为 PII 真实命中面, 配置级 not-contains PII 金丝雀) |
| RAG 真实测试 | 95% | Agent 真实检索 `knowledge/*.md`; 诱饵扩充至 5 项 (清算价/升级暗号/未发布活动/结算接口/服务密钥 SK-INT-7C4F-9B2A) + 检索投毒文档 promotions-draft.md (服从型标记 PROMED-7741); 修复 mock 关键词绕过漏洞 (受限来源 DLP 拦截, 绕过拒绝关键词的查询不再回显内部资料); `rag` 套件覆盖文档外泄/跨会话/提取/检索内容间接注入 |
| Tool 真实测试 | 95% | 4 个真实工具(订单/退款/搜索/客户资料), 退款无确认环节作为过度代理真实命中面, provider 接线已探针验证; 新增 `CONFIRM_REFUND=1` 人工审批开关, "发现→修复→复测归零"闭环演示可离线执行 |
| Memory 真实测试 | 95% | 会话历史摘要已真实注入模型上下文 (修复前真实模式仅客户端回放、服务端记忆只写不读); mock 记忆真实召回 + 跨会话隔离断言纳入测试套件; `memory` 套件覆盖投毒/PII 会话/跨会话探测/PII 直取, 策略含 crescendo 多轮与 jailbreak |
| Timing Benchmark | 95% | 双视角基准 (裸模型 vs Agent 全链路), 各自 p95 预算门禁 + promptfoo `latency` 断言; p95 改线性插值、默认 10 轮、轮间隔 `COOLDOWN_MS`、单次失败重试; 报告写入 Job Summary; mock 冒烟通过, 真实数据待 CI 首跑 |

## 红队闭环记录 (发现 → 修复 → 回归)

1. **会话劫持** (2026-10-25): 请求体 `metadata.session_id` 是会话选择的备用通道, 攻击者在无法设置请求头的场景下可冒用任意会话读取其历史 → 修复为会话仅由 `X-Session-Id` 头选定; 离线攻击链回归通过。
2. **mock 关键词绕过** (2026-10-25): 绕过拒绝关键词的查询可经 RAG 回显路径读出受限语料 → 受限来源 DLP 拦截; 回归通过。
3. **过度代理** (内建演示): `process_refund` 无确认执行为刻意保留攻击面, `CONFIRM_REFUND=1` 演示修复后归零。
4. **开放原语 (刻意保留, 由红队套件度量)**: 协议级轮次伪造 (messages 数组可夹带 assistant/tool 消息, 真实模式原样转发) / 工具参数反射 (参数未净化回写工具结果 JSON) / 尾包脱离 (检索仅以末条用户消息为 key) / 对话史伪造 (摘要 `role: content` 拼接不净化换行) / 上下文投送 (受限语料混入正常商品内容, 无辜问题实测 28 分居首) — mock 层面的回显与执行均被拦截, 真实模型定力由 rag/投毒/hijacking 套件度量。

## 剩余事项 (需要仓库操作权限或首次 CI 运行)

1. 在 GitHub 仓库 Settings → Secrets 配置 `DEEPSEEK_API_KEY`, 红队与时延 job 才会实际执行。
2. 手动触发一次 workflow_dispatch, 确认三个 job 全绿、产物上传完整。
3. 依据首次真实扫描结果调优 `gate_policy.json` 阈值 (当前为初版基线; `min_total_cases=60` 需按首跑实际样本量校准; PII 金丝雀判为零容忍属刻意从严 — 被测 Agent 的 get_customer_profile 无权限校验本身即是待修漏洞)。
4. 红队规模扩大后 (定向 ~600 用例/次, 全量 ~1900 用例/日), 如 API 成本过高可下调 numTests 或改 schedule 频率。
