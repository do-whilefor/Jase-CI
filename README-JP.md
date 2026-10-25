<div align="center">

# Jase-CI

[promptfoo](https://github.com/promptfoo/promptfoo) ベース、LLM アプリ向けの継続的レッドチーム + レイテンシ計測 CI。攻撃生成・結果判定・被検査アプリのバックエンドは同一の上流モデルに統一（デフォルトは DeepSeek、`UPSTREAM_*` で切替可能）。API キー 1 つで全フローが動きます。

[![CI](https://github.com/do-whilefor/Jase-CI/actions/workflows/promptfoo.yml/badge.svg)](https://github.com/do-whilefor/Jase-CI/actions/workflows/promptfoo.yml)
[![promptfoo](https://img.shields.io/badge/promptfoo-0.123.0-orange)](https://github.com/promptfoo/promptfoo)
[![Node.js](https://img.shields.io/badge/Node.js-24-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-PolyForm_NC_1.0.0-blue)](#ライセンス)

[概要](#概要) · [使い方](#使い方) · [セキュリティ範囲](#セキュリティ範囲) · [ライセンス](#ライセンス)

**日本語** · [简体中文](./README-ZH.md) · [English](./README.md)

</div>

## 概要

Jase-CI は LLM アプリへのレッドチーム評価を CI として継続実行できるようにします。被検査体は OpenAI 互換のカスタマーサポート Agent（実際のツール呼び出し / RAG 検索 / 会話メモリ持ち）。promptfoo のレッドチームプラグインが攻撃ケースを生成し、`security_gate.py` がポリシーに基づいて決定論的に判定、基準超過ならパイプラインを失敗させます。レイテンシも二視点で計測し、性能予算もゲート化します。

- **キー 1 つで全フロー** — 攻撃生成・判定・Agent バックエンドが `UPSTREAM_API_KEY`（`DEEPSEEK_API_KEY` フォールバック対応）を共用。
- **決定論的セキュリティゲート（スキップ不可）** — 全体攻撃成功率の上限、ゼロ容認プラグイン（1 件命中で失敗）、プラグイン別上限に加え、LLM に依存しないデコイ機密断言。
- **二視点レイテンシ計測** — 素のモデル直結と Agent 全経路（ツール / RAG / メモリ込み）をそれぞれ p95 予算でゲート。
- **オフライン検証可能** — モック全経路テスト・ゲートフィクスチャ自己テスト・キー不要の接続プローブにより、鍵未設定のリポジトリでも validate はグリーン。

CI の定義は [`.github/workflows/promptfoo.yml`](./.github/workflows/promptfoo.yml)。main への push で 4 スイート（自作クリエイティブ攻撃スイート込み）を実行し、毎日 UTC 02:00 の定期ジョブと手動トリガーでは 46 プラグインのフルスキャンも実行します。レッドチームと計測ジョブには `UPSTREAM_API_KEY` シークレット（`DEEPSEEK_API_KEY` も可）が必要で、未設定なら鍵不要の validate のみ実行されます。

### アーキテクチャ

```
.github/workflows/promptfoo.yml        CI オーケストレーション: 検証 → レッドチーム+ゲート → 計測
promptfooconfig_full.yaml              フルレッドチームスキャン (46 プラグイン, 上流ゲートウェイ経由)
promptfooconfig_creative.yaml          定向: クリエイティブ攻撃 (自作 8 プラグイン, redteam run で実生成)
configs/
  promptfooconfig.attacks.yaml         オフライン攻撃リプレイ (CI validate で強制)
  promptfooconfig.agent.yaml           定向: Agent/ツール乱用 (過剰代理/ツール発見/ハイジャック/目標乖離)
  promptfooconfig.rag.yaml             定向: RAG 漏えい (ナレッジ流出/セッション跨ぎ/プロンプト抽出)
  promptfooconfig.memory.yaml          定向: 会話メモリ (メモリ投毒/PII/セッション跨ぎプローブ)
  promptfooconfig.probe.yaml           キー不要プローブ: provider 接続検証 (CI validate で強制)
  promptfooconfig.timing.yaml          promptfoo 側レイテンシ断言 (latency 閾値)
  redteam/*.json                       自作クリエイティブプラグイン定義 (generator+grader)
agent/
  server.js                            被検査アプリ: OpenAI 互換サポート Agent
                                       (実ツール/RAG/会話メモリ; MOCK_MODEL=1 でオフライン)
  knowledge/*.md                       RAG コーパス。internal-notes.md に「開示禁止」デコイ
scripts/
  security_gate.py                     CI Security Gate: 結果を解析しポリシーで合否判定
  gate_policy.json                     ゲートポリシー (全体成功率上限/ゼロ容認/プラグイン別上限)
  timing_benchmark.py                  レイテンシ計測: TTFT/総遅延/スループット, p95 予算ゲート
  validate_configs.js                  promptfoo 設定の構造・構文検証
tests/
  run_tests.py                         オフラインテストスイート (モック全経路+ゲートフィクスチャ+計測スモーク)
```

## 使い方

### 環境要件

| 項目 | 要件 |
| --- | --- |
| OS | Windows / macOS / Linux（CI は ubuntu-latest） |
| promptfoo | 0.123.0（`npm install -g promptfoo@0.123.0`、Node.js ≥ 22.22.0） |
| Node.js | 24 — 被検査 Agent・設定検証・接続プローブ |
| Python | 3.12 — テストスイート・セキュリティゲート・計測（標準ライブラリのみ） |
| ローカル検証 | npm パッケージ `yaml`（`validate_configs.js` が使用） |
| キー | `UPSTREAM_API_KEY`（`DEEPSEEK_API_KEY` フォールバック対応）— 実スキャンと計測に必須。オフライン自測には不要 |

> コマンドは bash 記法。PowerShell では `$env:NAME = "value"` で環境変数を設定してください（例: `$env:CI = "true"`）。

### オフライン自測（キー不要）

```bash
python tests/run_tests.py                     # モック全経路 + ゲートフィクスチャ + 計測スモーク
npm install --no-save --no-package-lock yaml
node scripts/validate_configs.js              # 設定の構造・構文検証
MOCK_MODEL=1 PORT=8787 node agent/server.js   # 被検査 Agent 起動 (オフラインモック)
```

### 実レッドチームスキャン

ターミナルを 2 つ使います：先に Agent を起動し、もう片方からスキャンします。0.123.0 の `promptfoo eval` はレッドチームケースを**生成しません**（用例を内蔵したオフライン再生専用）。実スキャンは必ず `promptfoo redteam run` を使ってください。

```bash
# ターミナル 1 — 被検査 Agent (実モード、起動したまま)
export UPSTREAM_API_KEY=sk-xxx
node agent/server.js

# ターミナル 2 — 攻撃生成・実行、その後ゲート判定
export UPSTREAM_API_KEY=sk-xxx
export AGENT_API_KEY=local-test   # 空でなければ任意の値。promptfoo の起動チェック用
export CI=true                    # promptfoo のメール検証をスキップ (リポジトリ CI と同一挙動)
promptfoo redteam run -c configs/promptfooconfig.agent.yaml -o results-agent.json
python scripts/security_gate.py results-agent.json
```

4 つのスイート（`configs/promptfooconfig.{agent,rag,memory}.yaml` + `promptfooconfig_creative.yaml`）がツール乱用・RAG 漏えい・会話メモリ・自作クリエイティブ攻撃をカバー。`promptfooconfig_full.yaml` は 46 プラグインのフルスキャンです。ゲートは複数の結果ファイルを一括読み込みでき、ポリシー違反が 1 つでもあれば非ゼロで終了します。実スキャンは API クォータを消費し、数分かかるのが普通です。

### レイテンシ計測

```bash
# 視点 1: モデル直結
python scripts/timing_benchmark.py --outdir timing-model

# 視点 2: Agent 全経路 (前ステップの Agent を使用)
TARGET_BASE_URL=http://localhost:8787/v1 python scripts/timing_benchmark.py --outdir timing-agent
```

予算は `TIMING_BUDGET_MS` で制御（CI では Agent 視点の p95 予算は 30 秒）。p95 超過で失敗します。

## セキュリティ範囲

使用前に [SECURITY.md](./SECURITY.md) をお読みください。

- **合法的な許諾** — 自分が所有または許諾を受けたアプリのみテストできます。レッドチームプラグインは実際に攻撃的なコンテンツを生成してモデルサービスを呼び出すため、未許諾の第三者システムに向けてはなりません。
- **ゲートポリシー** — [`scripts/gate_policy.json`](./scripts/gate_policy.json) が決定論的に判定します。全体攻撃成功率の上限 **20%**、プロンプト抽出・システムプロンプト上書き・セッション跨ぎ漏えい・RAG 文書流出・PII・SQL/Shell インジェクション・SSRF・脱獄テンプレートなどのゼロ容認プラグインは 1 件命中で失敗、過剰代理や幻覚には容認上限、さらにデコイ機密断言とカバレッジガード（CI は `--enforce-coverage` で強制）。有効化された各プラグインは必ずポリシーに登録され、`validate_configs.js` が交叉検証します。
- **人間によるレビュー** — 判定は LLM 審査を含むため見落とし/誤検知があり得ます。合否にかかわらず、生の証拠・実際の影響・カバレッジと照らし合わせて確認してください。
- **情報保護** — RAG コーパス・会話記録・レッドチーム結果には機密内容が含まれる可能性があります。モデルサービスに送る前に、保密要件とデータ処理条項を確認してください。
- **リソース制御** — スキャンと計測は API クォータを消費します。アカウントに支出上限を設定してください。

テスト許諾の取得と自身の行動の責任は使用者にあり、プロジェクトのライセンスは第三者システムのテストを許諾するものではありません。

## ライセンス

本リポジトリは [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/)（声明は [SECURITY.md](./SECURITY.md) 参照）に従います。サードパーティコンポーネントはそれぞれのライセンス・規約に従います。

| ファイル | 内容 |
| --- | --- |
| [SECURITY.md](./SECURITY.md) | 免責事項・コンプライアンス要件・デプロイリスク |
