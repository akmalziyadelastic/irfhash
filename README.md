# irfHASH: Isolated Runtime Fortress (Hardened Agentic Secret Hub)

**irfHASH** is a personal, 100% local, zero-leak encrypted credential vault and execution gateway built for Desktop AI agents (**Claude Desktop / Claude Code**, **OpenAI Codex Desktop / CLI**, **Google Antigravity**, **Cursor**, and local agent workflows).

Instead of leaving plaintext `.env` files, API tokens, or credentials scattered across your laptop and AI chat transcripts, **irfHASH** locks every secret inside **AES-256-GCM + macOS Keychain**, lets your AI agents discover and call your connected systems without ever seeing the raw secret, and includes a 1-click **Chat Secret Sanitizer** that scrubs historical AI chat logs and leaves AI-readable pointers back to your local vault.

---

## Instant Setup: Just Give This Link to Your Desktop AI

You do not even need to run manual setup commands. Copy and paste this prompt into **Claude Desktop**, **OpenAI Codex Desktop**, **Antigravity**, or **Cursor**:

> *"Install and set up irfHASH from https://github.com/akmalziyadelastic/irfhash so you can manage my local credentials securely, scan my workspace for existing keys, verify which ones are active, and launch the local Control Center dashboard."*

### What Your AI Will Do Automatically
1. Clone this repository and run `bash install.sh`.
2. Register the `irfhash` skill and global instructions inside:
   * **Claude Desktop / Claude Code**: `~/.claude/skills/irfhash/SKILL.md` and `~/.claude/CLAUDE.md`
   * **OpenAI Codex Desktop / CLI**: `~/.codex/skills/irfhash/SKILL.md` and `~/.codex/AGENTS.md`
   * **Local Agent Directories**: `~/.agents/skills/irfhash/SKILL.md`
3. Run `irfhash scan` in memory to harvest existing API keys and tokens from your local files and chat logs, encrypt them into **macOS Keychain + AES-256-GCM**, and run read-only `GET` probes to mark each connection as `ACTIVE` or `EXPIRED`.
4. Launch the local **Control Center UI** at http://irfhash.localhost:8765 (or any custom local domain you choose).

### Or Install Manually in 10 Seconds
```bash
git clone https://github.com/akmalziyadelastic/irfhash.git ~/.irfhash-src
cd ~/.irfhash-src && bash install.sh
```

---

## Key Features Built for InfoSec Peace of Mind

### 1. Hardware-Backed AES-256-GCM + macOS Keychain Encryption
* **Zero Plaintext on Disk**: Master 256-bit keys live inside your **macOS Keychain** (`io.irfhash.vault.master`). Secrets are encrypted in memory via OpenSSL `EVP_aes_256_gcm` with per-record HKDF-SHA256 subkey derivation and authenticated tags (`vault.enc`).
* **Safe Metadata Catalog (`catalog.json`)**: Stores only the connection slug ID, your editable display name, system type, editable URL, environment tag (`TEST`, `UAT`, `DEV`, `PROD`, `PERSONAL`), verification status (`ACTIVE` vs `EXPIRED`), and a 7-character masked preview.

### 2. Zero-Ask, Zero-Leak Execution Middleware
* Once installed into `~/.claude/` and `~/.codex/`, your AI already knows about `irfhash` in every new chat without needing to ask.
* When you ask your AI to query Slack, Jira, GitHub, GitLab, Notion, Linear, Stripe, or any other system, the AI checks `irfhash list` and executes calls through `irfhash request` or `irfhash exec`.
* `irfHASH` injects the decrypted credential in memory and automatically scrubs any secret from stdout and stderr before returning the result to the AI.

### 3. 1-Click AI Chat Sanitizer & Redactor ("🛡️ Sanitize Chats")
* Clicking **🛡️ Sanitize Chats** in the Control Center UI (or running `irfhash sanitize` in the CLI) scans your local AI chat histories (`~/.claude`, `~/.codex`, `~/.gemini/antigravity/brain`) for any raw secret stored in your vault.
* It deletes the raw secret from the chat files and replaces it with a structured AI-readable pointer:
  ```text
  [REDACTED_BY_IRFHASH:id=slack-bot|system=slack|env=DEV|note=Secret secured in local irfHASH vault. AI agents: run 'irfhash request slack-bot <METHOD> <path>' to use without exposing credentials]
  ```
* When any AI reads that chat later, it immediately understands that the secret was redacted for security and knows the exact `irfhash` ID to call.

### 4. Hard PROD Write Lock & Native macOS Permission Prompts
* **Automatic PROD Guardrail**: Any connection tagged `PROD` is hard-blocked at the middleware layer from `POST`, `PUT`, `PATCH`, or `DELETE` mutations.
* **Per-Connection Agent Policies**: Choose between `Allow Read / Prompt Write`, `Prompt Every Time (macOS Native Dialog)`, `15m Session Lease`, or `LOCKED`, plus a global 1-click **Kill Switch** in the top bar.
* **Tamper-Evident Audit Trail**: Every verification, read, write, or blocked request is recorded in a SHA-256 hash-chained log (`audit.jsonl`).

### 5. Configurable Custom Local Domain (Bookmark & Star Easily)
* By default, the Control Center is accessible at http://irfhash.localhost:8765 (which resolves to `127.0.0.1` automatically in modern browsers).
* Click **🌐 Custom URL** in the top bar (or run `irfhash domain myvault.local --map-hosts`) to set any custom domain name (`irfhash.vault`, `berk.local`, `mykeys.box`, or any name you like) so you can bookmark or star it in your browser.

### 6. White Light Mode, Dark Mode & 1-Click "How to Train Your Dragon" Theme
* Opens in a clean **White Light Mode** by default with a 1-click **🌙 Dark Mode / ☀️ Light Mode** toggle.
* Includes an animated **Isle of Berk (Toothless & Light Fury)** guardian theme that can be enabled or disabled anytime with a single click on **🐉 Dragons: ON / OFF**.
* Includes **22 built-in application presets** (Slack, Jira, Stripe, Supabase, Vercel, Discord, Cloudflare, GitHub, GitLab, Google Cloud, Confluence, Notion, Linear, Okta, Datadog, PagerDuty, OpenAI, Anthropic, Azure OpenAI, LangSmith, Jina AI, and Custom REST/MCP).

---

## Everyday Workflow: Pasting New Keys in Chat

Whenever you want to add a new system, you do not even have to open the UI. Simply paste the URL and key in chat and tell your AI:
> *"Add this Slack token to my irfHASH registry as slack-main and sanitize the chat."*

Your AI will run `irfhash add` with the sanitize flag, encrypting the token into your vault and immediately scrubbing the raw token out of the chat transcript.
