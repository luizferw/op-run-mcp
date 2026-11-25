#!/usr/bin/env node
// op-run-mcp: MCP server (stdio) that runs commands with 1Password secrets injected as env vars.
// The agent sees secret names and masked output, never the values.
//
//   op-run-mcp                         start the MCP server
//   op-run-mcp store-token             read a service account token from stdin and store it
//   op-run-mcp list                    print the secret catalogue (names only)
//   op-run-mcp run NAME[,NAME] -- cmd  run a command with secrets, output masked
//   op-run-mcp import-env --vault V [--descriptions file.json] NAME [NAME...]
//                                      copy env vars of this process into 1Password items (needs write access)
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import fs from 'node:fs';
import { z } from 'zod';
import { Catalogue, ENV_NAME, VERSION, capture, connect, run, storeToken } from './core.mjs';

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
  throw new Error(`Unknown command: ${cmd}`);
}

main().catch((e) => { console.error(e.message); process.exit(1); });
