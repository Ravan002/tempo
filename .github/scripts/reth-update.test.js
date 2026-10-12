const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

test('repository adapter regression tests', () => {
  const result = spawnSync('python3', ['-m', 'unittest', 'discover', '-s', __dirname,
    '-p', 'test_prepare_reth_update.py', '-v'], {
    encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }, timeout: 30000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('publisher trust is pinned to the same shared revision as the caller', () => {
  const workflow = readFileSync(path.join(__dirname, '../workflows/update-reth.yml'), 'utf8');
  const policy = readFileSync(path.join(__dirname, '../sts/update-reth.sts.yaml'), 'utf8');
  const revision = workflow.match(/dependency-update\.yml@([0-9a-f]{40})/)[1];
  assert.ok(policy.includes(`dependency-update\\.yml@${revision}`));
  assert.match(policy, /max_ttl: 15m/);
  assert.doesNotMatch(workflow, /DEREK_UPDATE_RETH_TOKEN|amp-run|dangerously-allow-all/);
});
