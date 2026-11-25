# op-run-mcp

A small [MCP](https://modelcontextprotocol.io/) server that lets AI coding agents (Claude Code, Codex, Cursor…) **use** secrets stored in 1Password without ever **seeing** them.

The agent gets three tools:

| Tool | What it does |
|------|--------------|
| `list_secrets` | Names, vault, field names and description of the secrets it may use. Never values. |
| `run_with_secrets` | Runs a command with the chosen secrets as environment variables and returns the output with every value replaced by `[secret NAME]`. |
| `save_secret` | Creates an item or sets one field. The value comes from a file (deleted afterwards), from a command's stdout (never shown to the agent), or literally when the user already pasted it. Replacing an existing value needs `overwrite: true`. |

There is no tool that reveals or deletes a secret. You see and manage everything in the 1Password app.

> Not an official 1Password product. Built on the official [1Password JavaScript SDK](https://github.com/1Password/onepassword-sdk-js).

## Why

- **No approval prompt per secret.** It authenticates with a [1Password Service Account](https://developer.1password.com/docs/service-accounts/), so agents spawning new shells don't trigger the desktop app's authorization prompt every few minutes.
- **Least privilege.** The service account only sees the vault(s) you grant it (e.g. a dedicated `Agents` vault). `OP_VAULTS` adds a second fence inside the server.
- **Works on Windows.** The token is stored encrypted with DPAPI for your Windows user. The official 1Password Environments MCP server is currently macOS/Linux only.
- **Tiny.** Two source files, three pinned dependencies.

## Setup

1. **In 1Password:** create a vault (e.g. `Agents`) and a service account with access only to it. Give it write access if agents should store secrets with `save_secret` (or you use `import-env`); read-only otherwise.
2. **Add items** to that vault, any kind:
   - **Regular items** (Login, Database, API Credential…) with as many fields as you like, e.g. a Login `Staging admin` with `username` and `password`. The agent maps fields to variables when it runs a command.
   - **Single-value secrets** whose title is a variable name (`GITHUB_TOKEN`) can be requested by name alone.

   Without an explicit field, the value comes from the field named `credential`, `password`, `token`, `api key`, `secret`, `key` or `value`, or else the first concealed field. An optional text field named `description` is shown to the agent.
3. **Install and store the token:**

   ```sh
   git clone https://github.com/luizferw/op-run-mcp && cd op-run-mcp && npm ci
   # paste the token, then Enter and Ctrl+D (Linux/macOS) or Ctrl+Z, Enter (Windows)
   node src/index.mjs store-token
   ```

   The token is written to `%APPDATA%\op-run-mcp\token` encrypted with DPAPI (Windows), or to `~/.config/op-run-mcp/token` with mode `600` (Linux/macOS).

   **WSL:** instead of a second plaintext copy, point WSL at the Windows file (`OP_TOKEN_FILE=/mnt/c/Users/<you>/AppData/Roaming/op-run-mcp/token`). It is decrypted through `powershell.exe` interop.

4. **Register the server.**

   Claude Code:

   ```sh
   claude mcp add -s user op-run -e OP_VAULTS=Agents -- node /path/to/op-run-mcp/src/index.mjs
   ```

   Codex (`~/.codex/config.toml`):

   ```toml
   [mcp_servers.op-run]
   command = "node"
   args = ["/path/to/op-run-mcp/src/index.mjs"]
   env = { OP_VAULTS = "Agents" }
   ```

## Configuration

| Variable | Meaning |
|----------|---------|
| `OP_SERVICE_ACCOUNT_TOKEN` | Token in the environment. Takes precedence over the token file. |
| `OP_TOKEN_FILE` | Token file path (default above). Content `dpapi:<base64>` is decrypted with DPAPI. |
| `OP_ACCOUNT` | Use the 1Password desktop app instead of a service account (prompts for approval). |
| `OP_VAULTS` | Comma-separated vault names or IDs the server may use. Empty means every vault the account can see. |
| `OP_RUN_WSL_DISTRO` | WSL distro for `shell: "wsl"` (Windows only; default distro if unset). |

## Using it

`run_with_secrets` takes:

- `command` (PowerShell on Windows, bash elsewhere) **or** `argv` (program + arguments, no shell);
- `secrets`: `["GITHUB_TOKEN"]`, or a map from variable to item, such as
  `{ "APP_USER": { "item": "Staging admin", "field": "username" }, "APP_PASS": { "item": "Staging admin", "field": "password" }, "GH_TOKEN": "GITHUB_TOKEN", "X": "op://Agents/Item/field" }`;
- optional `cwd`, `timeout_seconds` (default 120, max 600; kills the whole process tree), `shell: "wsl"`.

Command line, same logic:

```sh
node src/index.mjs list
node src/index.mjs run GITHUB_TOKEN -- gh api user
# copy env vars of this process into new items (needs write access to the vault);
# --descriptions takes a JSON file {"NAME": "description"}
node src/index.mjs import-env --vault Agents GITHUB_TOKEN OPENAI_API_KEY
```

## Security notes

- **Masking is best effort.** Raw, base64, URL- and JSON-encoded forms are replaced in the output. A command that deliberately transforms a secret (hashes it, reverses it, splits it) or sends it somewhere else is not stopped. Keep your client's approval prompt on for `run_with_secrets` if you don't trust what the agent runs.
- **The agent runs as your user.** It can read the token file like any other file you own. DPAPI keeps the token encrypted at rest and out of config files and backups. It does not protect it from a process running as you. The real limit is what the service account can access: give agents a vault holding only what they may use.
- `OP_SERVICE_ACCOUNT_TOKEN` is removed from the environment of the commands it runs.
- Service accounts have [rate limits](https://developer.1password.com/docs/service-accounts/rate-limits/). The item list is cached for 60 seconds.

## Development

```sh
npm test
```

## License

MIT
