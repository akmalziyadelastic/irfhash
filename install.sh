#!/usr/bin/env bash
set -euo pipefail

echo "=================================================================="
echo "  irfHASH Installer"
echo "  Isolated Runtime Fortress: Hardened Agentic Secret Hub"
echo "=================================================================="

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/.irfhash"

mkdir -p "${INSTALL_DIR}"
cp -f "${REPO_DIR}/src/crypto_engine.py" "${INSTALL_DIR}/crypto_engine.py"
cp -f "${REPO_DIR}/src/vault_manager.py" "${INSTALL_DIR}/vault_manager.py"
cp -f "${REPO_DIR}/src/dashboard_server.py" "${INSTALL_DIR}/dashboard_server.py"
cp -f "${REPO_DIR}/src/scan_and_import.py" "${INSTALL_DIR}/scan_and_import.py"
cp -f "${REPO_DIR}/src/irfhash" "${INSTALL_DIR}/irfhash"
chmod +x "${INSTALL_DIR}/irfhash" "${INSTALL_DIR}/dashboard_server.py" "${INSTALL_DIR}/scan_and_import.py"

# Symlink irfhash onto PATH
if [ -d "/opt/homebrew/bin" ] && [ -w "/opt/homebrew/bin" ]; then
  ln -sf "${INSTALL_DIR}/irfhash" "/opt/homebrew/bin/irfhash"
  echo "[+] Linked CLI to /opt/homebrew/bin/irfhash"
elif [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
  ln -sf "${INSTALL_DIR}/irfhash" "/usr/local/bin/irfhash"
  echo "[+] Linked CLI to /usr/local/bin/irfhash"
else
  mkdir -p "${HOME}/.local/bin"
  ln -sf "${INSTALL_DIR}/irfhash" "${HOME}/.local/bin/irfhash"
  echo "[+] Linked CLI to ${HOME}/.local/bin/irfhash"
fi

# Install Skill & Auto-Context Rules for Claude Desktop / Claude Code
mkdir -p "${HOME}/.claude/skills/irfhash"
cp -f "${REPO_DIR}/skills/irfhash/SKILL.md" "${HOME}/.claude/skills/irfhash/SKILL.md"
if [ ! -f "${HOME}/.claude/CLAUDE.md" ] || ! grep -q "irfHASH" "${HOME}/.claude/CLAUDE.md"; then
  cat "${REPO_DIR}/CLAUDE.md" >> "${HOME}/.claude/CLAUDE.md"
fi
echo "[+] Installed irfHASH skill & global context for Claude Desktop (~/.claude)"

# Install Skill & Auto-Context Rules for OpenAI Codex Desktop / CLI
mkdir -p "${HOME}/.codex/skills/irfhash"
cp -f "${REPO_DIR}/skills/irfhash/SKILL.md" "${HOME}/.codex/skills/irfhash/SKILL.md"
if [ ! -f "${HOME}/.codex/AGENTS.md" ] || ! grep -q "irfHASH" "${HOME}/.codex/AGENTS.md"; then
  cat "${REPO_DIR}/AGENTS.md" >> "${HOME}/.codex/AGENTS.md"
fi
echo "[+] Installed irfHASH skill & global context for OpenAI Codex Desktop (~/.codex)"

# Install Skill for Antigravity / Global Agent Directories
mkdir -p "${HOME}/.agents/skills/irfhash"
cp -f "${REPO_DIR}/skills/irfhash/SKILL.md" "${HOME}/.agents/skills/irfhash/SKILL.md"
echo "[+] Installed irfHASH skill for Local Agents (~/.agents/skills/irfhash)"

# Run initial local credential scan & health check
echo "[+] Scanning local environment & chat folders for existing credentials..."
python3 "${INSTALL_DIR}/scan_and_import.py"

echo ""
echo "=================================================================="
echo "  irfHASH is installed and ready!"
echo "  Run: irfhash list        (view encrypted connections)"
echo "  Run: irfhash dashboard   (open http://irfhash.localhost:8765)"
echo "  Run: irfhash sanitize    (redact secrets from AI chat logs)"
echo "=================================================================="
