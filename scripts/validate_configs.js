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
      return require(path.join(base, 'yaml'));
    } catch { /* 下一个候选 */ }
  }
  return null;
}
yaml = loadYaml();
if (!yaml) {
  console.error('错误: 无法加载 yaml 模块。请先在项目根目录执行:');
  console.error('  npm install --no-save --no-package-lock yaml');
  console.error('或设置 PROMPTFOO_NODE_MODULES 指向含 yaml 的 node_modules 目录。');
  process.exit(2);
}

const CONFIG_DIR = path.join(__dirname, '..', 'configs');
const FILES = [
  ...fs.readdirSync(CONFIG_DIR).filter((f) => f.endsWith('.yaml')).map((f) => path.join(CONFIG_DIR, f)),
  path.join(__dirname, '..', 'promptfooconfig_full.yaml'),
  path.join(__dirname, '..', 'promptfooconfig_creative.yaml'),
];

// GitHub Actions 工作流也纳入语法校验
const WORKFLOW = path.join(__dirname, '..', '.github', 'workflows', 'promptfoo.yml');

let failed = false;
const fail = (msg) => { console.error(`  [FAIL] ${msg}`); failed = true; };
const ok = (msg) => console.log(`  [OK]   ${msg}`);

// 各套件启用的红队插件 -> 使用它的配置文件列表 (供策略一致性交叉校验)
const suitePlugins = new Map();

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
      const pluginIds = [];
      for (const p of rt.plugins) {
        if (typeof p === 'string' && p.length) {
          pluginIds.push(p);
          continue;
        }
        // 对象形: {id: <内置名 | file:// 定义路径>, numTests?: number} — custom plugin 引用
        if (p && typeof p === 'object' && typeof p.id === 'string' && p.id) {
          if (p.numTests !== undefined) {
            const n = Number(p.numTests);
            if (!(n > 0)) fail(`插件 '${p.id}' numTests 必须 > 0`);
            else if (n > 1000) fail(`插件 '${p.id}' numTests=${p.numTests} 超过上界 1000 (CI 成本保护)`);
          }
          if (p.id.startsWith('file://')) {
            const defPath = path.resolve(path.dirname(file), p.id.slice('file://'.length));
            try {
              const def = JSON.parse(fs.readFileSync(defPath, 'utf8'));
              if (!def.generator || !def.grader) {
                fail(`自定义插件 '${p.id}' 定义缺少 generator/grader`);
              } else {
                ok(`自定义插件 ${path.basename(p.id)} (id=${def.id || '默认'}, generator+grader)`);
              }
            } catch (e) {
              fail(`自定义插件 '${p.id}' 定义文件不可读或非 JSON: ${e.message}`);
            }
          }
          pluginIds.push(p.id);
          continue;
        }
        fail(`redteam.plugins 含非法条目: ${JSON.stringify(p)}`);
      }
      const dupes = pluginIds.filter((p, i) => pluginIds.indexOf(p) !== i);
      if (dupes.length) fail(`redteam.plugins 重复: ${[...new Set(dupes)].join(', ')}`);
      ok(`plugins: ${pluginIds.length} 个 (无重复)`);
      for (const p of pluginIds) {
        if (!suitePlugins.has(p)) suitePlugins.set(p, []);
        suitePlugins.get(p).push(rel);
      }
    }
    if (rt.numTests !== undefined) {
      const n = Number(rt.numTests);
      if (!(n > 0)) fail('redteam.numTests 必须 > 0');
      else if (n > 1000) fail(`redteam.numTests=${rt.numTests} 超过上界 1000 (CI 成本保护)`);
    }
    if (typeof rt.purpose !== 'string' || !rt.purpose) fail('redteam.purpose 缺失 (影响攻击生成质量)');
    // 自定义攻击策略 (custom:<变体>) 必须提供 strategyText 手稿
    if (Array.isArray(rt.strategies)) {
      for (const s of rt.strategies) {
        const sid = typeof s === 'string' ? s : s && s.id;
        if (s && typeof s === 'object' && typeof sid === 'string' && sid.startsWith('custom')) {
          if (!s.config || typeof s.config.strategyText !== 'string' || !s.config.strategyText.trim()) {
            fail(`自定义策略 '${sid}' 缺少 config.strategyText 手稿`);
          } else {
            ok(`自定义策略 '${sid}' (含手稿)`);
          }
        }
      }
    }
  } else {
    // 普通评测配置: prompts/tests 断言
    if (!Array.isArray(cfg.prompts) || cfg.prompts.length === 0) fail('缺少 prompts');
    if (Array.isArray(cfg.tests)) {
      // 每条 test 自带 assert, 或由 defaultTest.assert 统一提供均可
      const hasDefaultAssert =
        cfg.defaultTest && Array.isArray(cfg.defaultTest.assert) && cfg.defaultTest.assert.length > 0;
      for (let i = 0; i < cfg.tests.length; i++) {
        const asserts = cfg.tests[i] && cfg.tests[i].assert;
        if (!Array.isArray(asserts) || !asserts.length) {
          if (!hasDefaultAssert) fail(`tests[${i}] 缺少 assert (且无 defaultTest.assert 兜底)`);
        }
      }
      ok(`tests: ${cfg.tests.length} 条 (${hasDefaultAssert ? 'defaultTest 统一断言' : '均含 assert'})`);
    } else {
      fail('缺少 tests');
    }
  }

  // 模型凭证纪律 (协议无关): 任何 provider 配置内联 apiKey 都拒绝 — 凭证必须经
  // apiKeyEnvar 注入; 上游协议/厂商/模型由 UPSTREAM_* 环境变量决定, 配置不携带凭证
  const text = JSON.stringify(cfg);
  if (/["']apiKey["']\s*:/.test(text)) {
    fail('provider 配置使用了内联 apiKey, 凭证必须经 apiKeyEnvar 注入 (协议无关)');
  } else {
    ok('凭证经 apiKeyEnvar 注入, 无内联密钥');
  }
}

// gate_policy.json ↔ 套件插件一致性: 套件启用的插件必须登记零容忍或上限,
// 否则该插件只受整体成功率约束, 等于处于无单插件上限状态
const POLICY_FILE = path.join(__dirname, 'gate_policy.json');
if (fs.existsSync(POLICY_FILE)) {
  const failedBefore = failed;
  console.log('校验 gate_policy.json ↔ 红队套件插件一致性:');
  let policy = null;
  try {
    policy = JSON.parse(fs.readFileSync(POLICY_FILE, 'utf8'));
  } catch (e) {
    fail(`gate_policy.json 解析失败: ${e.message}`);
  }
  if (policy) {
    const zeroTol = new Set(policy.zero_tolerance_plugins || []);
    const capped = new Set(Object.keys(policy.plugin_max_success_rate || {}));
    for (const [plugin, usedIn] of suitePlugins) {
      if (!zeroTol.has(plugin) && !capped.has(plugin)) {
        fail(`插件 '${plugin}' (用于 ${usedIn.join(', ')}) 未在 gate_policy.json 登记零容忍或成功率上限`);
      }
    }
    for (const p of [...zeroTol, ...capped]) {
      if (!suitePlugins.has(p)) {
        console.warn(`  [WARN] 策略中的插件 '${p}' 未被任何套件启用`);
      }
    }
    if (failed === failedBefore) ok(`套件插件 ${suitePlugins.size} 个均已登记`);
  }
} else {
  console.warn('  [WARN] 未找到 gate_policy.json, 跳过策略一致性校验');
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
