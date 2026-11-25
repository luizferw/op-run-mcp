import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Catalogue, mask, primaryField, run } from '../src/core.mjs';

const items = {
  i1: { id: 'i1', title: 'GITHUB_TOKEN', vaultId: 'v1', category: 'ApiCredentials', fields: [
    { id: 'username', title: 'username', fieldType: 'Text', value: 'bot' },
    { id: 'credential', title: 'credential', fieldType: 'Concealed', value: 'ghp_supersecretvalue123' },
    { id: 'd', title: 'description', fieldType: 'Text', value: 'GitHub API' },
  ] },
  i2: { id: 'i2', title: 'Not an env name', vaultId: 'v1', category: 'Login', fields: [] },
  i3: { id: 'i3', title: 'DB', vaultId: 'v2', category: 'Database', fields: [
    { id: 'x', title: 'other', fieldType: 'Concealed', value: 'pg-pass-9876' },
  ] },
};
const fake = {
  vaults: { list: async () => [{ id: 'v1', title: 'Agents' }, { id: 'v2', title: 'Private' }] },
  items: {
    list: async (v) => Object.values(items).filter((i) => i.vaultId === v).map(({ fields, ...o }) => o),
    get: async (_v, id) => items[id],
  },
  secrets: { resolve: async (ref) => `resolved:${ref}` },
};

test('primaryField prefers well-known field names, then concealed', () => {
  assert.equal(primaryField(items.i1).value, 'ghp_supersecretvalue123');
  assert.equal(primaryField(items.i3).value, 'pg-pass-9876');
});

test('list exposes names, never values, and honours the vault allow-list', async () => {
  const c = new Catalogue(fake, { vaults: ['Agents'] });
  const list = await c.list();
  assert.deepEqual(list.map((x) => x.name), ['GITHUB_TOKEN']);
  assert.equal(list[0].description, 'GitHub API');
  assert.ok(!JSON.stringify(list).includes('ghp_'));
});

test('resolve by name, by field and refuses refs outside allowed vaults', async () => {
  const c = new Catalogue(fake, { vaults: ['Agents'] });
  assert.deepEqual((await c.resolve(['GITHUB_TOKEN'])).env, { GITHUB_TOKEN: 'ghp_supersecretvalue123' });
  assert.deepEqual((await c.resolve({ GH_USER: 'GITHUB_TOKEN.username' })).env, { GH_USER: 'bot' });
  assert.deepEqual((await c.resolve(['DB'])).missing, ['DB']);
  await assert.rejects(c.resolve({ X: 'op://Private/DB/other' }), /not allowed/);
  assert.equal((await c.resolve({ X: 'op://Agents/GITHUB_TOKEN/credential' })).env.X, 'resolved:op://Agents/GITHUB_TOKEN/credential');
});

test('mask replaces raw and encoded values', () => {
  const v = 'ghp_supersecretvalue123';
  const out = mask(`a ${v} b ${Buffer.from(v).toString('base64')}`, { GITHUB_TOKEN: v });
  assert.equal(out, 'a [secret GITHUB_TOKEN] b [secret GITHUB_TOKEN]');
});

test('run injects env and masks output', async () => {
  const command = process.platform === 'win32' ? 'Write-Output "v=$env:MY_SECRET"' : 'echo "v=$MY_SECRET"';
  const r = await run({ command, env: { MY_SECRET: 'abc123xyz' } });
  assert.equal(r.exitCode, 0);
  assert.match(r.output, /v=\[secret MY_SECRET\]/);
});

test('run with argv needs no shell and masks output', async () => {
  const r = await run({ argv: [process.execPath, '-e', 'console.log(process.env.MY_SECRET)'], env: { MY_SECRET: 'abc123xyz' } });
  assert.equal(r.exitCode, 0);
  assert.equal(r.output.trim(), '[secret MY_SECRET]');
});

test('timeout kills the process tree', async () => {
  const started = Date.now();
  const child = `require('child_process').spawn(process.execPath, ['-e', 'setTimeout(()=>{}, 60000)'], { stdio: 'inherit' }); setTimeout(()=>{}, 60000)`;
  const r = await run({ argv: [process.execPath, '-e', child], env: {}, timeoutSeconds: 1 });
  assert.equal(r.timedOut, true);
  assert.ok(Date.now() - started < 15_000, 'run() returned only after the grandchild exited');
});

test('rejects command and argv together', () => {
  assert.throws(() => run({ command: 'x', argv: ['y'], env: {} }), /exactly one/);
});
