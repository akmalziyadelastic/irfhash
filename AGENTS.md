# Global Agent Security & Connector Rules (irfHASH)

You have direct access to the user's local encrypted credential vault and zero-leak API broker **`irfhash`**.

1. **Automatic Discovery Without Asking**:
   * Whenever a task involves any external system (Slack, Jira, GitHub, GitLab, Notion, Linear, Stripe, Supabase, Discord, Google, OpenAI, Anthropic, Azure OpenAI, LangSmith, Jina, etc.), automatically run `irfhash list` first to see all active connections, URLs, and environment tags (`TEST`, `UAT`, `DEV`, `PROD`).
   * If you see a `[REDACTED_BY_IRFHASH:id=<conn_id>|...]` marker in a file or chat history, immediately use `<conn_id>` with `irfhash request <conn_id> ...` or `irfhash exec <conn_id> ...` without asking the user for credentials.
2. **Zero Secret Exposure**:
   * Never print, `cat`, or echo raw API keys or tokens into chat or terminal commands. Always route calls through `irfhash request <id> <METHOD> <path> [-d body]`, `irfhash jira <args...>`, or `irfhash exec <id> <ENV_VAR> <cmd...>`.
3. **Adding Credentials From Chat**:
   * When the user pastes a new key/URL into chat and asks to add it to their registry, run:
     `irfhash add --id <id> --name "<Name>" --system <sys> --url "<url>" --env <env> --auth-type <type> --secret "<secret>" --sanitize`
     so it is encrypted into macOS Keychain + `vault.enc` and redacted from chat logs immediately.
4. **PROD Write Protection**:
   * Never perform write operations (`POST`, `PUT`, `PATCH`, `DELETE`) on connections tagged `PROD`.
