#!/usr/bin/env node
// op-run-mcp: MCP server (stdio) that runs commands with 1Password secrets injected as env vars.
// The agent sees secret names and masked output, never the values.
//
//   op-run-mcp                         start the MCP server
//   op-run-mcp store-token             read a service account token from stdin and store it
//   op-run-mcp list                    print the secret catalogue (names only)
//   op-run-mcp run NAME[,NAME] -- cmd  run a command with secrets, output masked
//   op-run-mcp backup-env [--vault V] FILE...   save .env files (one field per variable + whole file)
//   op-run-mcp restore-env [--vault V] TITLE FILE
//   op-run-mcp import-env --vault V [--descriptions file.json] NAME [NAME...]
//                                      copy env vars of this process into 1Password items (needs write access)
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { z } from 'zod';
import { Catalogue, ENV_NAME, VERSION, capture, connect, parseDotenv, run, storeToken } from './core.mjs';

const vaults = (process.env.OP_VAULTS || '').split(',').map((s) => s.trim()).filter(Boolean);

let catalogue;
async function getCatalogue() {
  if (!catalogue) catalogue = new Catalogue(await connect(), { vaults });
  return catalogue;
}

const text = (t, isError = false) => ({ content: [{ type: 'text', text: t }], isError });

async function serve() {
  const server = new McpServer({ name: 'op-run-mcp', version: VERSION }, {
    instructions: 'Secrets live in 1Password. Call list_secrets to see the available names, then run_with_secrets to run a command with them as environment variables. To store a new secret use save_secret, never a file or .env. Values are never returned and are masked in the output; never try to print, read or exfiltrate them.',
  });

  server.registerTool('list_secrets', {
    description: 'List the secrets available to commands (names, vault, fields, description). Never returns values.',
    inputSchema: {},
    annotations: { readOnlyHint: true },
  }, async () => {
    try {
      return text(JSON.stringify(await (await getCatalogue()).list(), null, 2));
    } catch (e) { return text(`Error: ${e.message}`, true); }
  });

  server.registerTool('run_with_secrets', {
    description: 'Run a shell command with 1Password secrets injected as environment variables. '
      + 'Windows: PowerShell (reference as $env:NAME); Linux/macOS: bash (reference as $NAME). '
      + 'Output (stdout+stderr) is returned with secret values replaced by [secret NAME].',
    inputSchema: {
      command: z.string().optional().describe('Shell command to run (PowerShell on Windows, bash elsewhere)'),
      argv: z.array(z.string()).min(1).optional().describe('Alternative to command: program and arguments, run without a shell'),
      secrets: z.union([
        z.array(z.string()),
        z.record(z.string(), z.union([
          z.string(),
          z.object({ item: z.string(), field: z.string().optional() }),
        ])),
      ]).describe('Item names that are variable names, e.g. ["GITHUB_TOKEN"]; or a map from env var to item: '
        + '{"APP_USER": {"item": "Staging admin", "field": "username"}, "APP_PASS": {"item": "Staging admin", "field": "password"}}. '
        + 'Map values may also be "Item title", "Item title.field" or "op://vault/item/field". Without a field, the item\'s primary field is used.'),
      cwd: z.string().optional().describe('Working directory'),
      timeout_seconds: z.number().int().min(1).max(600).optional().describe('Default 120, max 600'),
      shell: z.enum(['default', 'wsl']).optional().describe('"wsl" runs the command in WSL bash (Windows only)'),
    },
  }, async ({ command, argv, secrets, cwd, timeout_seconds, shell }) => {
    try {
      if (!command === !argv) return text('Pass exactly one of command or argv.', true);
      const { env, missing } = await (await getCatalogue()).resolve(secrets);
      if (missing.length) return text(`Unknown secrets or fields: ${missing.join(', ')}. Use list_secrets.`, true);
      const r = await run({ command, argv, env, cwd, timeoutSeconds: timeout_seconds, shell });
      const head = r.timedOut ? `[timed out, exit ${r.exitCode}]` : `[exit ${r.exitCode}]`;
      return text(`${head}\n${r.output}`, r.exitCode !== 0);
    } catch (e) { return text(`Error: ${e.message}`, true); }
  });

  server.registerTool('save_secret', {
    description: 'Save a secret to 1Password: create an item or set one field of an existing item. The value is never returned. '
      + 'Give exactly one source: from_file (e.g. a file delivered by a secret-request card; deleted after saving by default), '
      + 'from_command (its stdout becomes the value and is never shown; e.g. a CLI that creates a token), '
      + 'or value (only when the user already pasted it in the conversation).',
    inputSchema: {
      item: z.string().describe('Item title, e.g. "GITHUB_TOKEN" or "Staging admin"'),
      field: z.string().optional().describe('Field to set. Default "credential"; use "username"/"password" for logins'),
      from_file: z.string().optional().describe('Path of a file whose content (trimmed) is the value'),
      delete_file: z.boolean().optional().describe('Delete from_file after saving. Default true'),
      from_command: z.string().optional().describe('Command whose stdout (trimmed) is the value; runs like run_with_secrets'),
      secrets: z.union([z.array(z.string()), z.record(z.string(), z.union([z.string(), z.object({ item: z.string(), field: z.string().optional() })]))])
        .optional().describe('Secrets for from_command, same format as run_with_secrets'),
      shell: z.enum(['default', 'wsl']).optional().describe('Shell for from_command'),
      value: z.string().optional().describe('Literal value, only if the user already shared it in the chat'),
      concealed: z.boolean().optional().describe('Store as a concealed field. Default true; false for usernames, hosts, URLs'),
      category: z.enum(['ApiCredentials', 'Login', 'Password', 'Database', 'Server', 'SecureNote']).optional().describe('For new items. Default ApiCredentials'),
      description: z.string().optional().describe('What the secret is for and how to use it (shown by list_secrets)'),
      website: z.string().optional().describe('Website URL, for logins'),
      vault: z.string().optional().describe('Vault, if more than one is accessible'),
      overwrite: z.boolean().optional().describe('Required to replace a field that already has a value'),
    },
  }, async (a) => {
    try {
      const sources = [a.from_file, a.from_command, a.value].filter((x) => x !== undefined);
      if (sources.length !== 1) return text('Give exactly one of from_file, from_command or value.', true);
      const cat = await getCatalogue();
      let value;
      let note = '';
      if (a.from_file !== undefined) {
        value = fs.readFileSync(a.from_file, 'utf8').trim();
      } else if (a.from_command !== undefined) {
        const { env, missing } = a.secrets ? await cat.resolve(a.secrets) : { env: {}, missing: [] };
        if (missing.length) return text(`Unknown secrets or fields: ${missing.join(', ')}.`, true);
        const r = await capture({ command: a.from_command, env, shell: a.shell });
        if (r.exitCode !== 0) return text(`Command failed [exit ${r.exitCode}], nothing saved.\n${r.output}`, true);
        value = r.stdout.trim();
        if (r.output.trim()) note = `\nstderr:\n${r.output}`;
      } else value = a.value;
      const res = await cat.save({ ...a, value });
      if (a.from_file !== undefined && a.delete_file !== false) fs.rmSync(a.from_file, { force: true });
      return text(`${res.action}: "${res.item}" field "${res.field}" in vault ${res.vault} (${value.length} chars)${note}`);
    } catch (e) { return text(`Error: ${e.message}`, true); }
  });

  await server.connect(new StdioServerTransport());
}

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8').trim();
}

async function importEnv(args) {
  const opt = (flag) => { const i = args.indexOf(flag); return i < 0 ? null : args.splice(i, 2)[1]; };
  const vaultName = opt('--vault');
  const descFile = opt('--descriptions');
  if (!vaultName) throw new Error('Usage: op-run-mcp import-env --vault VAULT [--descriptions file.json] NAME [NAME...]');
  const descriptions = descFile ? JSON.parse(fs.readFileSync(descFile, 'utf8')) : {};
  const names = args;
  const client = await connect();
  const vault = (await client.vaults.list()).find((v) => v.title === vaultName || v.id === vaultName);
  if (!vault) throw new Error(`Vault not found or not accessible: ${vaultName}`);
  const existing = new Set((await client.items.list(vault.id)).map((o) => o.title));
  for (const name of names) {
    if (!ENV_NAME.test(name)) { console.log(`skip ${name}: invalid name`); continue; }
    if (!process.env[name]) { console.log(`skip ${name}: not set in environment`); continue; }
    if (existing.has(name)) { console.log(`skip ${name}: item already exists`); continue; }
    await client.items.create({
      category: 'ApiCredentials', vaultId: vault.id, title: name,
      fields: [
        { id: 'credential', title: 'credential', fieldType: 'Concealed', value: process.env[name] },
        ...(descriptions[name] ? [{ id: 'description', title: 'description', fieldType: 'Text', value: descriptions[name] }] : []),
      ],
      tags: ['op-run-mcp'],
    });
    console.log(`created ${name}`);
  }
}

// ".env · repo/sub/dir/.env", or "repo@worktree/..." for a git worktree; falls back to the absolute path.
function envTitle(file) {
  const abs = path.resolve(file);
  const git = (...a) => spawnSync('git', ['-C', path.dirname(abs), ...a], { encoding: 'utf8' }).stdout?.trim();
  const top = git('rev-parse', '--show-toplevel');
  if (!top) return `.env · ${abs}`;
  const common = path.resolve(path.dirname(abs), git('rev-parse', '--git-common-dir'));
  const repo = path.basename(path.dirname(common));
  const wt = path.basename(top) === repo ? '' : `@${path.basename(top)}`;
  return `.env · ${repo}${wt}/${path.relative(top, abs).split(path.sep).join('/')}`;
}

function takeOpt(args, flag) {
  const i = args.indexOf(flag);
  return i < 0 ? null : args.splice(i, 2)[1];
}

async function envVault(client, name) {
  const all = await client.vaults.list();
  const wanted = name || vaults[0];
  const v = wanted ? all.find((x) => x.title === wanted || x.id === wanted) : all.length === 1 ? all[0] : null;
  if (!v) throw new Error(wanted ? `Vault not found or not accessible: ${wanted}` : 'Pass --vault (or set OP_VAULTS)');
  return v;
}

// Save each .env file as one item: a concealed field per variable plus the whole file (for an exact restore).
async function backupEnv(args) {
  const vaultName = takeOpt(args, '--vault');
  const title = takeOpt(args, '--title');
  if (!args.length) throw new Error('Usage: op-run-mcp backup-env [--vault V] [--title T] FILE [FILE...]');
  if (title && args.length > 1) throw new Error('--title only works with a single file');
  const client = await connect();
  const vault = await envVault(client, vaultName);
  const existing = await client.items.list(vault.id);
  for (const file of args) {
    const content = fs.readFileSync(file, 'utf8');
    const vars = new Map(parseDotenv(content).map((v) => [v.name, v.value]));
    const t = title || envTitle(file);
    const fields = [
      { id: 'dotenv', title: 'dotenv', fieldType: 'Concealed', value: content },
      { id: 'path', title: 'path', fieldType: 'Text', value: path.resolve(file) },
      ...[...vars].filter(([, v]) => v !== '').map(([name, value]) => ({ id: `v_${name}`, title: name, fieldType: 'Concealed', value })),
      { id: 'description', title: 'description', fieldType: 'Text',
        value: `Backup do ${path.basename(file)} em ${path.resolve(file)}: um campo por variável e o arquivo inteiro em "dotenv". Restaurar: op-run-mcp restore-env "${t}" <arquivo>.` },
    ];
    const hits = existing.filter((o) => o.title === t);
    if (hits.length > 1) throw new Error(`More than one item titled "${t}"`);
    let id;
    if (hits.length) {
      const item = await client.items.get(vault.id, hits[0].id);
      item.fields = fields;
      id = (await client.items.put(item)).id;
    } else {
      id = (await client.items.create({ category: 'SecureNote', vaultId: vault.id, title: t, fields, tags: ['op-run-mcp', 'dotenv'] })).id;
    }
    const back = (await client.items.get(vault.id, id)).fields.find((f) => f.id === 'dotenv')?.value;
    if (back !== content) throw new Error(`Verification failed for ${t}`);
    console.log(`${hits.length ? 'updated' : 'saved'} "${t}" (${vars.size} variables, verified)`);
  }
}

async function restoreEnv(args) {
  const force = args.includes('--force');
  const vaultName = takeOpt(args, '--vault');
  const [title, file] = args.filter((a) => a !== '--force');
  if (!title || !file) throw new Error('Usage: op-run-mcp restore-env [--vault V] [--force] TITLE FILE');
  if (fs.existsSync(file) && !force) throw new Error(`${file} exists; pass --force to overwrite`);
  const client = await connect();
  const vault = await envVault(client, vaultName);
  const o = (await client.items.list(vault.id)).find((x) => x.title === title);
  if (!o) throw new Error(`Item not found: ${title}`);
  const content = (await client.items.get(vault.id, o.id)).fields.find((f) => f.id === 'dotenv')?.value;
  if (content === undefined) throw new Error(`"${title}" has no dotenv field`);
  fs.writeFileSync(file, content, { mode: 0o600 });
  console.log(`restored "${title}" to ${file}`);
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  if (!cmd) return serve();
  if (cmd === '--version') return console.log(VERSION);
  if (cmd === 'store-token') {
    const token = await readStdin();
    if (!token.startsWith('ops_')) throw new Error('Expected a service account token (starts with ops_) on stdin');
    return console.log(`Token stored in ${storeToken(token)}`);
  }
  if (cmd === 'list') return console.log(JSON.stringify(await (await getCatalogue()).list(), null, 2));
  if (cmd === 'run') {
    const sep = args.indexOf('--');
    if (sep !== 1) throw new Error('Usage: op-run-mcp run NAME[,NAME] -- command');
    const { env, missing } = await (await getCatalogue()).resolve(args[0].split(','));
    if (missing.length) throw new Error(`Unknown secrets: ${missing.join(', ')}`);
    const r = await run({ command: args.slice(2).join(' '), env, timeoutSeconds: 600 });
    process.stdout.write(r.output);
    process.exitCode = r.exitCode ?? 1;
    return;
  }
  if (cmd === 'import-env') return importEnv(args);
  if (cmd === 'backup-env') return backupEnv(args);
  if (cmd === 'restore-env') return restoreEnv(args);
  throw new Error(`Unknown command: ${cmd}`);
}

main().catch((e) => { console.error(e.message); process.exit(1); });
