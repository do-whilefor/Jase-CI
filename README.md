<div align="center">

# Jase-CI

Continuous red-teaming + latency-benchmark CI for LLM apps, built on [promptfoo](https://github.com/promptfoo/promptfoo). Attack generation, result judging and the target app backend share one upstream model — DeepSeek by default, swappable via `UPSTREAM_*`.

[![CI](https://github.com/do-whilefor/Jase-CI/actions/workflows/promptfoo.yml/badge.svg)](https://github.com/do-whilefor/Jase-CI/actions/workflows/promptfoo.yml)
[![promptfoo](https://img.shields.io/badge/promptfoo-0.123.0-orange)](https://github.com/promptfoo/promptfoo)
[![Node.js](https://img.shields.io/badge/Node.js-24-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-PolyForm_NC_1.0.0-blue)](#license)

[Overview](#overview) · [Usage](#usage) · [Security Scope](#security-scope) · [License](#license)

**English** · [简体中文](./README-ZH.md) · [日本語](./README-JP.md)

</div>

## Overview

Jase-CI turns red-teaming of an LLM app into a sustainable CI loop. The target is an OpenAI-compatible customer-service Agent (real tool calls / RAG retrieval / session memory). promptfoo red-team plugins generate attack cases, `security_gate.py` judges results deterministically against a policy file, and the pipeline fails when limits are crossed. A dual-view latency benchmark turns performance budgets into gates as well.

- **One key runs everything** — attack generation, judging and the Agent backend share `UPSTREAM_API_KEY` (falls back to `DEEPSEEK_API_KEY`).
- **Deterministic, non-skippable security gate** — overall attack-success-rate cap, zero-tolerance plugins (a single hit fails), per-plugin caps, plus LLM-free decoy-secret assertions.
- **Dual-view latency benchmark** — raw model direct vs full Agent chain (tools / RAG / memory), each with its own p95 budget gate.
- **Offline-verifiable** — mock end-to-end tests, gate fixture self-tests and a key-free provider probe keep the validate job green in repos with no secrets configured.

CI orchestration lives in [`.github/workflows/promptfoo.yml`](./.github/workflows/promptfoo.yml): pushes to main run the four targeted suites (incl. the self-built creative-attack suite); the daily UTC 02:00 schedule and manual triggers add the 46-plugin full scan. The red-team and timing jobs need the `UPSTREAM_API_KEY` secret (`DEEPSEEK_API_KEY` also accepted); without it, only the key-free validate job runs.

### Architecture

```
.github/workflows/promptfoo.yml        CI orchestration: validate → redteam + security gate → timing
promptfooconfig_full.yaml              Full red-team scan (46 plugins, via upstream gateway)
promptfooconfig_creative.yaml          Targeted: 8 self-built creative plugins (redteam run, real generation)
configs/
  promptfooconfig.attacks.yaml         Offline attack replay (enforced in CI validate job)
  promptfooconfig.agent.yaml           Targeted: Agent/tool abuse (excessive agency / tool discovery / hijacking / goal misalignment)
  promptfooconfig.rag.yaml             Targeted: RAG leakage (knowledge exfiltration / cross-session / prompt extraction)
  promptfooconfig.memory.yaml          Targeted: session memory (poisoning / PII sessions / cross-session probing)
  promptfooconfig.probe.yaml           Key-free probe: verifies provider wiring (enforced in CI validate job)
  promptfooconfig.timing.yaml          promptfoo-side latency assertions (latency thresholds)
  redteam/*.json                       Self-built creative plugin definitions (generator + grader)
agent/
  server.js                            App under test: OpenAI-compatible customer-service Agent
                                       (real tools / RAG / session memory; MOCK_MODEL=1 for offline)
  knowledge/*.md                       RAG corpus; internal-notes.md contains "do-not-disclose" decoys
scripts/
  security_gate.py                     CI Security Gate: parses results, judges pass/fail against policy
  gate_policy.json                     Gate policy (overall ASR cap / zero-tolerance plugins / per-plugin caps)
  timing_benchmark.py                  Timing benchmark: TTFT / total latency / throughput, p95 budget gate
  validate_configs.js                  promptfoo config structure & syntax validation
tests/
  run_tests.py                         Offline test suite (mock end-to-end + gate fixtures + timing smoke)
```

## Usage

### Requirements

| Item | Requirement |
| --- | --- |
| OS | Windows / macOS / Linux (CI runs on ubuntu-latest) |
| promptfoo | 0.123.0 (`npm install -g promptfoo@0.123.0`, needs Node.js ≥ 22.22.0) |
| Node.js | 24 — target Agent, config validation, wiring probe |
| Python | 3.12 — test suite, security gate, latency benchmark (stdlib only) |
| Local validation | npm package `yaml` (parsed by `validate_configs.js`) |
| Key | `UPSTREAM_API_KEY` (falls back to `DEEPSEEK_API_KEY`) — required for real scans and benchmarks; offline tests need none |

> Commands are bash-style. In PowerShell set variables with `$env:NAME = "value"` (e.g. `$env:CI = "true"`).

### Offline self-test (no keys needed)

```bash
python tests/run_tests.py                     # mock end-to-end + gate fixtures + timing smoke
npm install --no-save --no-package-lock yaml
node scripts/validate_configs.js              # config structure & syntax validation
MOCK_MODEL=1 PORT=8787 node agent/server.js   # start target Agent (offline mock mode)
```

### Real red-team scan

Two terminals: start the Agent first, then scan from the other one. Note that `promptfoo eval` does **not** generate red-team cases in 0.123.0 (it only runs suites that ship their own tests); real scans must use `promptfoo redteam run`.

```bash
# Terminal 1 — target Agent (real mode, keep it running)
export UPSTREAM_API_KEY=sk-xxx
node agent/server.js

# Terminal 2 — generate attacks, run them, then gate
export UPSTREAM_API_KEY=sk-xxx
export AGENT_API_KEY=local-test   # any non-empty value; passes promptfoo's startup check
export CI=true                    # skips promptfoo's red-team email verification, same as repo CI
promptfoo redteam run -c configs/promptfooconfig.agent.yaml -o results-agent.json
python scripts/security_gate.py results-agent.json
```

Four targeted suites cover tool abuse, RAG leakage, session memory and the self-built creative attacks (`configs/promptfooconfig.{agent,rag,memory}.yaml` + `promptfooconfig_creative.yaml`); `promptfooconfig_full.yaml` is the 46-plugin full scan. The gate accepts multiple result files at once and exits non-zero on any policy violation. Real scans consume model API quota and typically take several minutes.

### Latency benchmark

```bash
# View 1: raw model direct
python scripts/timing_benchmark.py --outdir timing-model

# View 2: full Agent chain (with the Agent from the previous step)
TARGET_BASE_URL=http://localhost:8787/v1 python scripts/timing_benchmark.py --outdir timing-agent
```

Budgets are controlled by `TIMING_BUDGET_MS` (Agent-view p95 budget is 30s in CI); exceeding p95 fails the run.

## Security Scope

Read [SECURITY.md](./SECURITY.md) before use.

- **Legal authorization** — only test apps you own or are authorized to test. The red-team plugins generate real attack content and call model services; never point this pipeline at unauthorized third-party systems.
- **Gate policy** — [`scripts/gate_policy.json`](./scripts/gate_policy.json) judges results deterministically: overall attack-success-rate cap of **20%**; zero-tolerance plugins (prompt extraction, system prompt override, cross-session leakage, RAG exfiltration, PII, SQL/shell injection, SSRF, jailbreak templates) fail on a single hit; tolerated caps for excessive agency / hallucination; plus decoy-secret assertions and coverage guardrails enforced in CI with `--enforce-coverage`. Every enabled plugin must be registered in the policy, cross-checked by `validate_configs.js`.
- **Human review** — gate verdicts include LLM judging and can miss or misfire; review passes and failures against the raw evidence, real impact and coverage.
- **Information protection** — RAG corpus, session records and red-team results may contain sensitive content; check confidentiality requirements and the provider's data-processing terms before sending anything to a model service.
- **Resource control** — scans and benchmarks consume API quota; set a spend limit on the account.

You are responsible for obtaining test authorization and for your own actions; the project license grants no authorization to test third-party systems.

## License

This repository is licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) (statement in [SECURITY.md](./SECURITY.md)). Third-party components remain under their own licenses and terms.

| File | Content |
| --- | --- |
| [SECURITY.md](./SECURITY.md) | Disclaimer, compliance requirements, deployment risks |
