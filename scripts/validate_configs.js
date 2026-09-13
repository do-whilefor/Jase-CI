#!/usr/bin/env node
/**
 * 配置校验 — 对所有 promptfoo YAML 配置做语法与结构检查。
 * (promptfoo 0.123 无 validate/dry-run 子命令, 该脚本补上 CI 前置校验)
 *
 * 依赖: `yaml` 包 — 通过 NODE_PATH 指向 promptfoo 安装目录解析:
 *   CI:  npm i -g promptfoo && NODE_PATH=$(npm root -g) node scripts/validate_configs.js
 * 本地: NODE_PATH=<promptfoo 的 node_modules> node scripts/validate_configs.js
 *
 * 退出码: 0 = 全部通过; 1 = 存在错误。
 */
'use strict';

const fs = require('fs');
const path = require('path');

let yaml;
const yamlSearchPaths = [];
function loadYaml() {
  try {
    return require('yaml');
  } catch { /* 继续探测 */ }
  // npm i -g promptfoo 后, yaml 在 <npm root -g>/promptfoo/node_modules 下
  let globalRoot = '';
  try {
    globalRoot = require('child_process').execSync('npm root -g', { encoding: 'utf8' }).trim();
  } catch { /* npm 不可用时跳过 */ }
  for (const base of [process.env.PROMPTFOO_NODE_MODULES, globalRoot && path.join(globalRoot, 'promptfoo', 'node_modules'), globalRoot]) {
    if (!base) continue;
    try {
      const mod = require(path.join(base, 'yaml'));
      yamlSearchPaths.push(base);
      return mod;
    } catch { /* 下一个候选 */ }
  }
  return null;
}
yaml = loadYaml();
if (!yaml) {
  console.error('错误: 无法加载 yaml 模块。请先安装 promptfoo (npm i -g promptfoo),');
  console.error('或设置 PROMPTFOO_NODE_MODULES 指向 promptfoo 的 node_modules 目录。');
  process.exit(2);
}

const CONFIG_DIR = path.join(__dirname, '..', 'configs');
const FILES = [
  ...fs.readdirSync(CONFIG_DIR).filter((f) => f.endsWith('.yaml')).map((f) => path.join(CONFIG_DIR, f)),
  path.join(__dirname, '..', 'promptfooconfig_full.yaml'),
];

// GitHub Actions 工作流也纳入语法校验
const WORKFLOW = path.join(__dirname, '..', '.github', 'workflows', 'promptfoo.yml');

let failed = false;
const fail = (msg) => { console.error(`  [FAIL] ${msg}`); failed = true; };
const ok = (msg) => console.log(`  [OK]   ${msg}`);

for (const file of FILES) {
  const rel = path.relative(path.join(__dirname, '..'), file);
  console.log(`校验 ${rel}:`);
  let cfg;
  try {
    cfg = yaml.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    fail(`YAML 语法错误: ${e.message}`);
    continue;
  }
  if (!cfg || typeof cfg !== 'object') { fail('配置为空'); continue; }

  // targets 检查
  if (!Array.isArray(cfg.targets) || cfg.targets.length === 0) {
    fail('缺少 targets 或为空');
  } else {
    for (const t of cfg.targets) {
      if (!t || typeof t.id !== 'string' || !t.id) {
        fail('target 缺少 id');
        continue;
      }
      // promptfoo 路由规则: id 为 http(s) URL 时走 HttpProvider (要求 config 带 body 模板);
      // OpenAI 兼容端点必须用 id: openai:chat:<model> + config.apiBaseUrl
      if (/^https?:\/\//i.test(t.id) && !(t.config && t.config.body)) {
        fail(`target '${t.id}' 形如 URL 将被解析为 HttpProvider, 缺少 config.body; ` +
          'OpenAI 兼容端点应改用 id: openai:chat:<model> + config.apiBaseUrl');
      }
    }
    ok(`targets: ${cfg.targets.length} 个`);
  }

  // 红队配置检查
  if (cfg.redteam) {
    const rt = cfg.redteam;
    if (!rt.provider || typeof rt.provider.id !== 'string') fail('redteam.provider.id 缺失');
    if (!Array.isArray(rt.plugins) || rt.plugins.length === 0) {
      fail('redteam.plugins 为空');
    } else {
      const dupes = rt.plugins.filter((p, i) => rt.plugins.indexOf(p) !== i);
      if (dupes.length) fail(`redteam.plugins 重复: ${[...new Set(dupes)].join(', ')}`);
      if (!rt.plugins.every((p) => typeof p === 'string' && p.length)) fail('redteam.plugins 含非法条目');
      ok(`plugins: ${rt.plugins.length} 个 (无重复)`);
    }
    if (rt.numTests !== undefined && !(Number(rt.numTests) > 0)) fail('redteam.numTests 必须 > 0');
    if (typeof rt.purpose !== 'string' || !rt.purpose) fail('redteam.purpose 缺失 (影响攻击生成质量)');
  } else {
    // 普通评测配置: prompts/tests 断言
    if (!Array.isArray(cfg.prompts) || cfg.prompts.length === 0) fail('缺少 prompts');
    if (Array.isArray(cfg.tests)) {
      for (let i = 0; i < cfg.tests.length; i++) {
        const asserts = cfg.tests[i] && cfg.tests[i].assert;
        if (!Array.isArray(asserts) || !asserts.length) fail(`tests[${i}] 缺少 assert`);
      }
      ok(`tests: ${cfg.tests.length} 条 (均含 assert)`);
    } else {
      fail('缺少 tests');
    }
  }

  // DeepSeek 接入一致性: 涉及 deepseek 的 provider 必须用 env var 传 key
  const text = JSON.stringify(cfg);
  if (text.includes('deepseek') && text.includes('apiKey:')) {
    fail('DeepSeek 配置使用了内联 apiKey, 应使用 apiKeyEnvar: DEEPSEEK_API_KEY');
  } else if (text.includes('deepseek')) {
    ok('DeepSeek 凭证通过 apiKeyEnvar 注入');
  }
}

// GitHub Actions 工作流语法校验
if (fs.existsSync(WORKFLOW)) {
  console.log('校验 .github/workflows/promptfoo.yml:');
  try {
    const wf = yaml.parse(fs.readFileSync(WORKFLOW, 'utf8'));
    if (!wf || !wf.jobs || typeof wf.jobs !== 'object') {
      fail('工作流缺少 jobs 定义');
    } else {
      for (const [name, job] of Object.entries(wf.jobs)) {
        if (!job || !Array.isArray(job.steps) || job.steps.length === 0) {
          fail(`job '${name}' 缺少 steps`);
        }
        if (job['runs-on'] === undefined) {
          fail(`job '${name}' 缺少 runs-on`);
        }
      }
      ok(`jobs: ${Object.keys(wf.jobs).join(', ')}`);
    }
  } catch (e) {
    fail(`工作流 YAML 语法错误: ${e.message}`);
  }
}

console.log(failed ? '\n配置校验: 未通过 ❌' : '\n配置校验: 全部通过 ✅');
process.exit(failed ? 1 : 0);
