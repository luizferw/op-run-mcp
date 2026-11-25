// Core logic, independent of MCP: auth, item lookup, masking and command execution.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';

export const VERSION = '0.1.0';
export const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const PRIMARY_FIELDS = ['credential', 'password', 'token', 'api key', 'apikey', 'secret', 'key', 'value'];
const DESCRIPTION_FIELDS = ['description', 'descricao', 'descrição', 'notes'];

export function defaultTokenFile() {
  const base = process.platform === 'win32'
    ? process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming')
    : process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  return path.join(base, 'op-run-mcp', 'token');
}

// Windows: the token file holds "dpapi:<base64>", encrypted for the current Windows user.
// Also works from WSL through interop (powershell.exe), so WSL can share the Windows token file.
function dpapi(op, input) {
  const wslenv = process.platform === 'win32' ? {} : { WSLENV: [process.env.WSLENV, 'OPRUN_IN'].filter(Boolean).join(':') };
  const ps = `Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String($env:OPRUN_IN); `
    + (op === 'protect'
      ? `[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($b,$null,'CurrentUser'))`
      : `[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser'))`);
  const r = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], {
    env: { ...process.env, ...wslenv, OPRUN_IN: Buffer.from(input, op === 'protect' ? 'utf8' : 'base64').toString('base64') },
    encoding: 'utf8', windowsHide: true,
  });
  if (r.status !== 0) throw new Error(`DPAPI ${op} failed: ${(r.stderr || '').trim()}`);
  const out = r.stdout.trim();
  return op === 'protect' ? out : Buffer.from(out, 'base64').toString('utf8');
}

export function readToken(env = process.env) {
  if (env.OP_SERVICE_ACCOUNT_TOKEN) return env.OP_SERVICE_ACCOUNT_TOKEN.trim();
  const file = env.OP_TOKEN_FILE || defaultTokenFile();
  if (!fs.existsSync(file)) return null;
  const raw = fs.readFileSync(file, 'utf8').trim();
  return raw.startsWith('dpapi:') ? dpapi('unprotect', raw.slice(6)).trim() : raw;
}

export function storeToken(token, file = process.env.OP_TOKEN_FILE || defaultTokenFile()) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const content = process.platform === 'win32' ? `dpapi:${dpapi('protect', token.trim())}` : token.trim();
  fs.writeFileSync(file, `${content}\n`, { mode: 0o600 });
  if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
  return file;
}

export async function connect(env = process.env) {
  const { createClient, DesktopAuth } = await import('@1password/sdk');
  const token = readToken(env);
  const auth = token || (env.OP_ACCOUNT ? new DesktopAuth(env.OP_ACCOUNT) : null);
  if (!auth) {
    throw new Error('No credentials: set OP_SERVICE_ACCOUNT_TOKEN, store one with `op-run-mcp store-token`, or set OP_ACCOUNT to use the desktop app.');
  }
  return createClient({ auth, integrationName: 'op-run-mcp', integrationVersion: VERSION });
}

const norm = (s) => s.trim().toLowerCase();

export function primaryField(item) {
  const fields = item.fields.filter((f) => f.value);
  for (const want of PRIMARY_FIELDS) {
    const f = fields.find((x) => norm(x.title) === want || norm(x.id) === want);
    if (f) return f;
  }
  return fields.find((f) => f.fieldType === 'Concealed') || null;
}

function description(item) {
  const f = item.fields.find((x) => DESCRIPTION_FIELDS.includes(norm(x.title)) && x.fieldType !== 'Concealed');
  return f?.value || '';
}

// A catalogue of the items the agent may use. Values never leave this module except through run().
export class Catalogue {
  constructor(client, { vaults = [], ttlMs = 60_000 } = {}) {
    this.client = client;
    this.allowed = vaults.map(norm).filter(Boolean);
    this.ttlMs = ttlMs;
    this.cache = null;
  }

  async vaults() {
    const all = await this.client.vaults.list();
    return this.allowed.length ? all.filter((v) => this.allowed.includes(norm(v.title)) || this.allowed.includes(v.id)) : all;
  }

  async items() {
    if (this.cache && Date.now() - this.cache.at < this.ttlMs) return this.cache.items;
    const out = [];
    for (const v of await this.vaults()) {
      for (const o of await this.client.items.list(v.id)) out.push({ ...o, vaultTitle: v.title });
    }
    this.cache = { at: Date.now(), items: out };
    return out;
  }

  // Every item is listed: env-style secrets (title = variable name) and regular items
  // such as logins or databases, whose fields are mapped to variables by the caller.
  async list() {
    const res = [];
    for (const o of await this.items()) {
      const item = await this.client.items.get(o.vaultId, o.id);
      const p = primaryField(item);
      res.push({
        name: o.title,
        vault: o.vaultTitle,
        category: o.category,
        primary_field: p?.title || null,
        fields: item.fields.filter((f) => f.value && !DESCRIPTION_FIELDS.includes(norm(f.title))).map((f) => f.title),
        websites: (o.websites || []).map((w) => w.url).filter(Boolean),
        description: description(item),
      });
    }
    return res.sort((a, b) => a.name.localeCompare(b.name));
  }

  // spec: ["NAME", ...] (titles that are env var names)
  //   or { ENV_VAR: "Item title" | "Item title.field" | { item, field? } | "op://vault/item/field" }
  async resolve(spec) {
    const wanted = Array.isArray(spec) ? Object.fromEntries(spec.map((n) => [n, n])) : spec;
    const env = {};
    const missing = [];
    for (const [envName, ref] of Object.entries(wanted)) {
      if (!ENV_NAME.test(envName)) {
        throw new Error(`Invalid environment variable name: ${envName}. For items whose title is not a variable name, pass a map such as {"APP_PASSWORD": {"item": "${envName}", "field": "password"}}.`);
      }
      if (typeof ref === 'string' && ref.startsWith('op://')) {
        await this.assertAllowedRef(ref);
        env[envName] = await this.client.secrets.resolve(ref);
        continue;
      }
      const label = typeof ref === 'string' ? ref : `${ref.item}${ref.field ? `.${ref.field}` : ''}`;
      const found = await this.find(ref);
      if (!found) { missing.push(label); continue; }
      const item = await this.client.items.get(found.item.vaultId, found.item.id);
      const f = found.field
        ? item.fields.find((x) => norm(x.title) === norm(found.field) || x.id === found.field)
        : primaryField(item);
      if (!f?.value) { missing.push(label); continue; }
      env[envName] = f.value;
    }
    return { env, missing };
  }

  // "Title" or "Title.field" (titles may contain dots: the exact title wins, then the last dot splits).
  async find(ref) {
    const items = await this.items();
    const byTitle = (t) => items.filter((x) => x.title === t);
    const one = (t) => {
      const hits = byTitle(t);
      if (hits.length > 1) throw new Error(`More than one item titled "${t}"; use an op:// reference with the vault`);
      return hits[0];
    };
    if (typeof ref === 'object') {
      const item = one(ref.item);
      return item ? { item, field: ref.field } : null;
    }
    const exact = one(ref);
    if (exact) return { item: exact };
    const dot = ref.lastIndexOf('.');
    if (dot < 1) return null;
    const item = one(ref.slice(0, dot));
    return item ? { item, field: ref.slice(dot + 1) } : null;
  }

  async assertAllowedRef(ref) {
    if (!this.allowed.length) return;
    const vault = decodeURIComponent(ref.slice(5).split('/')[0]);
    const ok = (await this.vaults()).some((v) => norm(v.title) === norm(vault) || v.id === vault);
    if (!ok) throw new Error(`Vault not allowed: ${vault}`);
  }
}

// Replace every value (and common encodings of it) with [secret NAME].
export function mask(text, secrets) {
  const pairs = [];
  for (const [name, value] of Object.entries(secrets)) {
    if (!value || value.length < 4) continue;
    const forms = new Set([value, value.trim(), Buffer.from(value).toString('base64'), encodeURIComponent(value), JSON.stringify(value).slice(1, -1)]);
    for (const line of value.split(/\r?\n/)) if (line.trim().length >= 12) forms.add(line.trim());
    for (const f of forms) if (f.length >= 4) pairs.push([f, `[secret ${name}]`]);
  }
  pairs.sort((a, b) => b[0].length - a[0].length);
  let s = text;
  for (const [from, to] of pairs) s = s.split(from).join(to);
  return s;
}

// Kill the whole process tree, not only the shell.
function killTree(child) {
  if (!child.pid) return;
  try {
    if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true });
    else process.kill(-child.pid, 'SIGKILL');
  } catch { child.kill('SIGKILL'); }
}

export function run({ command, argv, env, cwd, timeoutSeconds = 120, shell = 'default', maxOutput = 1_000_000 }) {
  if (!command === !argv?.length) throw new Error('Pass exactly one of command or argv');
  const names = Object.keys(env);
  const base = { ...process.env, ...env };
  delete base.OP_SERVICE_ACCOUNT_TOKEN;
  const detached = process.platform !== 'win32';
  let child;
  if (argv?.length) {
    if (shell === 'wsl') throw new Error('argv cannot be combined with shell "wsl"; use command');
    child = spawn(argv[0], argv.slice(1), { cwd: cwd || undefined, env: base, windowsHide: true, detached });
  } else if (shell === 'wsl') {
    if (process.platform !== 'win32') throw new Error('shell "wsl" is only available on Windows');
    const distro = process.env.OP_RUN_WSL_DISTRO;
    const args = [...(distro ? ['-d', distro] : []), '--exec', 'bash', '-lc', command];
    child = spawn('wsl.exe', args, { env: { ...base, WSLENV: [process.env.WSLENV, ...names].filter(Boolean).join(':') }, windowsHide: true });
  } else if (process.platform === 'win32') {
    child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
      `[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; ${command}`], { cwd: cwd || undefined, env: base, windowsHide: true });
  } else {
    child = spawn('bash', ['-lc', command], { cwd: cwd || undefined, env: base, detached });
  }
  child.stdin.end();
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    let truncated = false;
    let timedOut = false;
    const collect = (d) => {
      // Keep a margin over maxOutput so a secret cut at the boundary is still masked before truncation.
      if (size > maxOutput * 2) { truncated = true; return; }
      chunks.push(d); size += d.length;
    };
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);
    const timer = setTimeout(() => { timedOut = true; killTree(child); }, Math.min(timeoutSeconds, 600) * 1000);
    let finished = false;
    const done = (code, extra = '') => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      let out = mask(Buffer.concat(chunks).toString('utf8') + extra, env);
      if (truncated || out.length > maxOutput) out = `${out.slice(0, maxOutput)}\n[output truncated]`;
      resolve({ exitCode: code, timedOut, output: out });
    };
    child.on('error', (e) => done(null, `\n${e.message}`));
    child.on('close', (c) => done(c));
  });
}
