#!/usr/bin/env python3
"""
irfHASH Generic Local Credential Scanner & Importer
Scans local .env files and AI chat folders in memory for standard API keys and tokens,
encrypts them into the local AES-256-GCM + macOS Keychain vault, and runs safe read-only
GET probes to mark each connection as ACTIVE or EXPIRED.

Strictly outputs ONLY masked metadata. Never prints raw secrets.
"""

import os
import re
import sys
from typing import Dict, Set

from vault_manager import IrfHashVault

PATTERNS = [
    ("github", "GitHub Personal Access Token", "https://api.github.com", "Bearer", "Authorization", "Bearer ", re.compile(r"\b(ghp_[0-9A-Za-z]{30,50}|github_pat_[0-9A-Za-z_]{40,100})\b")),
    ("slack", "Slack Workspace Bot/User Token", "https://slack.com/api", "Bearer", "Authorization", "Bearer ", re.compile(r"\b(xox[bpae]-[0-9A-Za-z-]{20,120})\b")),
    ("openai", "OpenAI API Key", "https://api.openai.com/v1", "Bearer", "Authorization", "Bearer ", re.compile(r"\b(sk-[A-Za-z0-9_-]{32,120})\b")),
    ("anthropic", "Anthropic Claude API Key", "https://api.anthropic.com/v1", "CustomHeader", "x-api-key", "", re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{32,140})\b")),
    ("langsmith", "LangSmith Tracing API Key", "https://api.smith.langchain.com", "CustomHeader", "x-api-key", "", re.compile(r"\b(lsv2_[A-Za-z0-9_]{30,90})\b")),
    ("jina", "Jina Reader & Embeddings Key", "https://r.jina.ai", "Bearer", "Authorization", "Bearer ", re.compile(r"\b(jina_[A-Za-z0-9_-]{30,100})\b")),
    ("google-api", "Google Cloud / API Key", "https://www.googleapis.com", "CustomHeader", "X-Goog-Api-Key", "", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")),
    ("diagram-api", "Diagram API REST API Key", "https://api.stripe.com/v1", "Bearer", "Authorization", "Bearer ", re.compile(r"\b(key-[A-Za-z0-9+/=_-]{40,200})\b")),
]


def scan_directory(root_dir: str, vault: IrfHashVault, seen_secrets: Set[str]) -> int:
    count = 0
    if not os.path.exists(root_dir):
        return 0

    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [
            d for d in dirnames if d not in (".git", "node_modules", ".venv", "venv", "__pycache__", ".irfhash", "irfhash")
        ]
        for fn in filenames:
            if not (
                fn.startswith(".env")
                or fn.endswith((".env", ".jsonl", ".json", ".yaml", ".yml", ".md", ".py", ".sh", ".creds"))
            ):
                continue
            fp = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(fp) > 25 * 1024 * 1024:
                    continue
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            # 1. Check standard token patterns
            for sys_name, label, default_url, auth_t, h_name, h_prefix, pat in PATTERNS:
                for match in pat.findall(content):
                    if match in seen_secrets:
                        continue
                    seen_secrets.add(match)
                    count += 1
                    cid = f"{sys_name}-key-{count}"
                    vault.upsert_connection(
                        conn_id=cid,
                        name=f"{label} #{count} ({fn})",
                        system=sys_name,
                        url=default_url,
                        environment="DEV",
                        auth_type=auth_t,
                        secret_value=match,
                        header_name=h_name,
                        header_prefix=h_prefix,
                        notes=f"Auto-discovered in {fn}",
                        source_ref=fn,
                        actor="auto-scanner",
                    )

            # 2. Check structured KEY=VALUE pairs in .env files
            if fn.startswith(".env") or fn.endswith(".env"):
                urls_in_file = re.findall(r"https?://[^\s\"\x27#]+", content)
                primary_url = urls_in_file[0] if urls_in_file else "https://api.example.com"
                for line in content.splitlines():
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    m = re.match(r"^([A-Z0-9_]{3,60})\s*=\s*[\"\x27]?([^\"\x27\s#]{16,250})[\"\x27]?", s)
                    if not m:
                        continue
                    k_name, k_val = m.group(1), m.group(2)
                    if k_val.startswith("http") or k_val in seen_secrets:
                        continue
                    if any(w in k_name for w in ("API_KEY", "SECRET", "TOKEN", "PASSWORD", "PAT")):
                        seen_secrets.add(k_val)
                        count += 1
                        slug = k_name.lower().replace("_", "-")[:26] + f"-{count}"
                        env_tag = "PROD" if "PROD" in k_name else ("UAT" if "UAT" in k_name else "DEV")
                        vault.upsert_connection(
                            conn_id=slug,
                            name=f"{k_name} ({fn})",
                            system=k_name.split("_")[0].lower(),
                            url=primary_url,
                            environment=env_tag,
                            auth_type="Bearer",
                            secret_value=k_val,
                            header_name="Authorization",
                            header_prefix="Bearer ",
                            notes=f"Imported from {fn}",
                            source_ref=fn,
                            actor="auto-scanner",
                        )
    return count


def main():
    vault = IrfHashVault()
    seen: Set[str] = set(vault.get_all_raw_secrets_for_scrubbing())

    targets = sys.argv[1:] if len(sys.argv) > 1 else [
        os.getcwd(),
        os.path.expanduser("~/.claude"),
        os.path.expanduser("~/.codex"),
        os.path.expanduser("~/.gemini/antigravity/brain"),
    ]

    added = 0
    for t in targets:
        added += scan_directory(os.path.abspath(t), vault, seen)

    cat = vault.load_catalog().get("connections", {})
    print(f"Scan finished: {added} new credentials encrypted into irfHASH ({len(cat)} total in vault).")
    if added > 0:
        print("Running safe read-only health verification...")
        for cid in list(cat.keys()):
            vault.verify_connection(cid, timeout=6, actor="auto-scanner")
    print("Done. Run 'irfhash list' or 'irfhash dashboard' to view your connections.")


if __name__ == "__main__":
    main()
