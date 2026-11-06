---
name: irfhash
description: Personal local encrypted connector & zero-leak credential gateway (irfHASH: Isolated Runtime Fortress: Hardened Agentic Secret Hub). Automatically check and use irfhash whenever the user asks to connect to, query, verify, or call any external system (Slack, Jira, GitHub, GitLab, Notion, Linear, Stripe, Supabase, Discord, OpenAI, Anthropic, Azure OpenAI, LangSmith, Jina, or any custom API), or when the user pastes credentials in chat and asks to add them to their registry.
metadata:
  short-description: Zero-leak local encrypted credential vault and API broker for AI agents
---

# irfHASH: Isolated Runtime Fortress (Hardened Agentic Secret Hub)

`irfHASH` is the user's personal, 100% local, AES-256-GCM + macOS Keychain encrypted credential vault and zero-leak execution broker (`irfhash` CLI).

## First-Time Setup (If `irfhash` Is Not Yet Installed)
If the user gave you this repository URL and `which irfhash` is not found on `$PATH`:
1. Clone this repository to `~/.irfhash-src` and run `bash install.sh`.
2. Run `irfhash scan` to discover and encrypt existing local credentials from `.env` files and chat logs, and verify which keys are `ACTIVE` vs `EXPIRED`.
3. Start the local Control Center dashboard in the background (`irfhash dashboard`) and share `http://irfhash.localhost:8765` with the user.

## Automatic Zero-Ask Behavior for AI Agents (Claude Desktop, Codex Desktop, Antigravity, Cursor)
1. **Check `irfhash list` Automatically**:
   * Whenever the user mentions an external system or asks you to fetch/update data in any system, do not ask for credentials first. Run `irfhash list` immediately to see if an active connection already exists in the registry.
   * If a chat transcript or file contains `[REDACTED_BY_IRFHASH:id=<conn_id>|...]`, use that `<conn_id>` directly via `irfhash request <conn_id> ...` or `irfhash exec <conn_id> ...` without asking the user to re-paste the secret.
2. **Zero Secrets in Chat or Command History**:
   * Never read, `cat`, or echo raw API keys, `.env` secrets, or tokens in terminal output or chat responses.
   * Always execute HTTP requests via `irfhash request <id> <METHOD> <path>` and CLI commands via `irfhash exec <id> <ENV_VAR> <cmd...>` (or `irfhash jira ...`). `irfHASH` decrypts the secret in memory, enforces PROD write-lock guardrails, logs a SHA-256 hash-chained audit record, and scrubs any secret from stdout/stderr before returning output to you.
3. **Adding New Connections Pasted in Chat**:
   * Whenever the user pastes a new key, token, or URL in chat and asks you to add it to their registry, run:
     ```bash
     irfhash add --id <slug> --name "<Friendly Name>" --system <system> --url "<url>" --env <TEST|DEV|UAT|PROD> --auth-type <ApiKey|Bearer|Basic|CustomHeader> --secret "<secret>" --sanitize
     ```
   * Passing `--sanitize` automatically encrypts the secret into macOS Keychain + `vault.enc` AND scrubs the raw secret out of local AI chat logs, replacing it with an `[REDACTED_BY_IRFHASH:id=<slug>|...]` pointer.

## CLI Reference
* `irfhash list` (list all connections safely with zero secrets exposed)
* `irfhash scan [dirs...]` (auto-discover and encrypt existing local credentials)
* `irfhash request <id> <METHOD> <path> [-d json]` (execute authenticated HTTP call with output scrubbing)
* `irfhash add --id <id> --name "<Name>" --system <sys> --url "<url>" --secret "<sec>" --sanitize` (encrypt new credential & redact from chat)
* `irfhash sanitize [--dry-run]` (redact all vault secrets from AI chat transcripts and replace with AI-readable `irfHASH` pointers)
* `irfhash domain <custom-domain> [--map-hosts]` (set custom bookmarkable local domain, e.g. `irfhash.localhost` or `irfhash.vault`)
* `irfhash verify [id]` (verify live status: `ACTIVE` vs `EXPIRED`)
* `irfhash dashboard` (launch Control Center UI on `http://irfhash.localhost:8765`)
