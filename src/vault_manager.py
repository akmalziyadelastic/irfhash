#!/usr/bin/env python3
"""
irfHASH Vault Manager & Policy Engine
Isolated Runtime Fortress: Hardened Agentic Secret Hub

Manages:
- Encrypted secret storage (data/vault.enc + macOS Keychain)
- Non-secret editable connection catalog (data/catalog.json)
- Cryptographically chained audit log (data/audit.jsonl)
- Native macOS permission prompts & PROD write-lock guardrails
- Live read-only health verification (ACTIVE vs EXPIRED)
- Output redaction scrubber & AI chat log sanitizer
- Custom local domain routing
"""

import base64
import datetime
import getpass
import hashlib
import json
import os
import re
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Any, List, Optional, Tuple

from crypto_engine import (
    get_or_create_master_key,
    aes_256_gcm_encrypt,
    aes_256_gcm_decrypt,
    store_secret_in_keychain,
    delete_secret_from_keychain,
    mask_secret_preview,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("IRFHASH_DATA_DIR") or os.path.join(BASE_DIR, "data")
CATALOG_PATH = os.path.join(DATA_DIR, "catalog.json")
VAULT_ENC_PATH = os.path.join(DATA_DIR, "vault.enc")
AUDIT_LOG_PATH = os.path.join(DATA_DIR, "audit.jsonl")
LEASES_PATH = os.path.join(DATA_DIR, "leases.json")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")

_VAULT_LOCK = threading.RLock()


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds")


class IrfHashVault:
    def __init__(self):
        os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
        self._ensure_files()

    def _ensure_files(self):
        if not os.path.exists(CATALOG_PATH):
            self._save_json_atomic(CATALOG_PATH, {"version": 1, "connections": {}})
        if not os.path.exists(SETTINGS_PATH):
            self._save_json_atomic(
                SETTINGS_PATH,
                {
                    "global_lockdown": False,
                    "enforce_prod_write_block": True,
                    "default_permission_mode": "ALLOW_READ_ASK_WRITE",
                    "session_lease_minutes": 15,
                    "custom_domain": "irfhash.localhost",
                    "dashboard_port": 8765,
                    "owner": getpass.getuser(),
                },
            )
        if not os.path.exists(LEASES_PATH):
            self._save_json_atomic(LEASES_PATH, {})
        if not os.path.exists(VAULT_ENC_PATH):
            self._save_encrypted_vault({})

    def _save_json_atomic(self, path: str, data: Any):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    def _load_encrypted_vault(self) -> Dict[str, Dict[str, Any]]:
        if not os.path.exists(VAULT_ENC_PATH):
            return {}
        with open(VAULT_ENC_PATH, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        if not raw:
            return {}
        envelope = json.loads(raw)
        master_key = get_or_create_master_key()
        plaintext = aes_256_gcm_decrypt(master_key, envelope, aad=b"irfhash.vault.v1")
        return json.loads(plaintext.decode("utf-8"))

    def _save_encrypted_vault(self, secrets_map: Dict[str, Dict[str, Any]]):
        master_key = get_or_create_master_key()
        plaintext = json.dumps(secrets_map, sort_keys=True).encode("utf-8")
        envelope = aes_256_gcm_encrypt(master_key, plaintext, aad=b"irfhash.vault.v1")
        self._save_json_atomic(VAULT_ENC_PATH, envelope)

    def load_catalog(self) -> Dict[str, Any]:
        with open(CATALOG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_catalog(self, catalog: Dict[str, Any]):
        self._save_json_atomic(CATALOG_PATH, catalog)

    def load_settings(self) -> Dict[str, Any]:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_settings(self, settings: Dict[str, Any]):
        self._save_json_atomic(SETTINGS_PATH, settings)

    def log_audit(
        self,
        action: str,
        conn_id: str,
        decision: str,
        detail: str = "",
        method: str = "",
        target: str = "",
        actor: str = "agent",
    ):
        """Appends a tamper-evident hash-chained entry to data/audit.jsonl."""
        prev_hash = "0" * 64
        if os.path.exists(AUDIT_LOG_PATH):
            try:
                with open(AUDIT_LOG_PATH, "rb") as f:
                    lines = f.read().splitlines()
                    if lines:
                        last_entry = json.loads(lines[-1].decode("utf-8"))
                        prev_hash = last_entry.get("hash", prev_hash)
            except Exception:
                pass

        record = {
            "timestamp": _now_iso(),
            "actor": actor,
            "action": action,
            "connection_id": conn_id,
            "method": method,
            "target": target,
            "decision": decision,
            "detail": detail,
            "prev_hash": prev_hash,
        }
        canonical = json.dumps(record, sort_keys=True).encode("utf-8")
        record["hash"] = hashlib.sha256(canonical).hexdigest()

        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        try:
            os.chmod(AUDIT_LOG_PATH, 0o600)
        except Exception:
            pass

    def get_audit_logs(self, limit: int = 200) -> List[Dict[str, Any]]:
        if not os.path.exists(AUDIT_LOG_PATH):
            return []
        entries = []
        with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
        return list(reversed(entries[-limit:]))

    def upsert_connection(
        self,
        conn_id: str,
        name: str,
        system: str,
        url: str,
        environment: str = "TEST",
        auth_type: str = "ApiKey",
        secret_value: Optional[str] = None,
        extra_secrets: Optional[Dict[str, str]] = None,
        header_name: str = "Authorization",
        header_prefix: str = "ApiKey ",
        extra_headers: Optional[Dict[str, str]] = None,
        status: str = "UNVERIFIED",
        status_detail: str = "",
        permission_mode: str = "ALLOW_READ_ASK_WRITE",
        notes: str = "",
        source_ref: str = "",
        actor: str = "system",
    ) -> Dict[str, Any]:
        with _VAULT_LOCK:
            catalog = self.load_catalog()
            conns = catalog.setdefault("connections", {})
            existing = conns.get(conn_id, {})

            env_upper = environment.upper()
            prod_lock = True if env_upper == "PROD" else existing.get("prod_write_lock", False)

            masked = existing.get("masked_preview", "(no secret stored)")
            if secret_value is not None or extra_secrets is not None:
                vault = self._load_encrypted_vault()
                current_sec = vault.get(conn_id, {})
                if secret_value is not None:
                    current_sec["secret"] = secret_value
                    masked = mask_secret_preview(secret_value)
                if extra_secrets:
                    current_sec.setdefault("extra", {}).update(extra_secrets)
                    if secret_value is None and "client_secret" in extra_secrets:
                        masked = mask_secret_preview(extra_secrets["client_secret"])
                vault[conn_id] = current_sec
                self._save_encrypted_vault(vault)
                store_secret_in_keychain(conn_id, current_sec)

            now = _now_iso()
            entry = {
                "id": conn_id,
                "name": name,
                "system": system.lower(),
                "url": url,
                "environment": env_upper,
                "auth_type": auth_type,
                "header_name": header_name,
                "header_prefix": header_prefix,
                "extra_headers": extra_headers if extra_headers is not None else existing.get("extra_headers", {}),
                "masked_preview": masked,
                "status": status if status != "UNVERIFIED" or "status" not in existing else existing["status"],
                "status_detail": status_detail or existing.get("status_detail", ""),
                "permission_mode": existing.get("permission_mode", permission_mode),
                "prod_write_lock": prod_lock,
                "notes": notes if notes else existing.get("notes", ""),
                "source_ref": source_ref if source_ref else existing.get("source_ref", ""),
                "created_at": existing.get("created_at", now),
                "updated_at": now,
                "last_verified_at": existing.get("last_verified_at", None),
                "last_used_at": existing.get("last_used_at", None),
                "use_count": existing.get("use_count", 0),
            }
            conns[conn_id] = entry
            self.save_catalog(catalog)
            self.log_audit("UPSERT_CONNECTION", conn_id, "ALLOWED", f"Updated '{name}' ({env_upper})", actor=actor)
            return entry

    def update_metadata(self, conn_id: str, updates: Dict[str, Any], actor: str = "user") -> Dict[str, Any]:
        with _VAULT_LOCK:
            catalog = self.load_catalog()
            conns = catalog.get("connections", {})
            if conn_id not in conns:
                raise KeyError(f"Connection '{conn_id}' not found")
            entry = conns[conn_id]

            editable_fields = [
                "name",
                "system",
                "url",
                "environment",
                "auth_type",
                "header_name",
                "header_prefix",
                "extra_headers",
                "permission_mode",
                "prod_write_lock",
                "notes",
                "status",
                "status_detail",
            ]
            for k in editable_fields:
                if k in updates and updates[k] is not None:
                    if k == "environment":
                        entry[k] = str(updates[k]).upper()
                        if entry[k] == "PROD":
                            entry["prod_write_lock"] = True
                    else:
                        entry[k] = updates[k]

            if "secret_value" in updates and updates["secret_value"]:
                new_sec = str(updates["secret_value"]).strip()
                vault = self._load_encrypted_vault()
                sec_obj = vault.get(conn_id, {})
                sec_obj["secret"] = new_sec
                vault[conn_id] = sec_obj
                self._save_encrypted_vault(vault)
                store_secret_in_keychain(conn_id, sec_obj)
                entry["masked_preview"] = mask_secret_preview(new_sec)
                entry["status"] = "UNVERIFIED"
                entry["status_detail"] = "Secret updated; ready to verify"

            entry["updated_at"] = _now_iso()
            self.save_catalog(catalog)
            self.log_audit("UPDATE_METADATA", conn_id, "ALLOWED", f"Edited fields: {list(updates.keys())}", actor=actor)
            return entry

    def delete_connection(self, conn_id: str, actor: str = "user") -> bool:
        with _VAULT_LOCK:
            catalog = self.load_catalog()
            conns = catalog.get("connections", {})
            if conn_id not in conns:
                return False
            name = conns[conn_id].get("name", conn_id)
            del conns[conn_id]
            self.save_catalog(catalog)

            vault = self._load_encrypted_vault()
            if conn_id in vault:
                del vault[conn_id]
                self._save_encrypted_vault(vault)
            delete_secret_from_keychain(conn_id)
            self.log_audit("DELETE_CONNECTION", conn_id, "ALLOWED", f"Deleted '{name}'", actor=actor)
            return True

    def _get_secret_obj(self, conn_id: str) -> Dict[str, Any]:
        vault = self._load_encrypted_vault()
        return vault.get(conn_id, {})

    def get_all_raw_secrets_for_scrubbing(self) -> List[str]:
        """Returns list of non-trivial secret strings solely for in-memory output redaction."""
        vault = self._load_encrypted_vault()
        items = []
        for _, obj in vault.items():
            s = obj.get("secret", "")
            if s and len(s) >= 8:
                items.append(s)
            extra = obj.get("extra", {})
            if isinstance(extra, dict):
                for _, ev in extra.items():
                    if isinstance(ev, str) and len(ev) >= 8:
                        items.append(ev)
        items.sort(key=len, reverse=True)
        return items

    def scrub_output(self, text: str) -> str:
        """Scrubs any known secret value from output before returning to an AI agent."""
        if not text:
            return text
        scrubbed = text
        for sec in self.get_all_raw_secrets_for_scrubbing():
            if sec in scrubbed:
                scrubbed = scrubbed.replace(sec, "[REDACTED_BY_IRFHASH]")
        return scrubbed

    def check_and_authorize(
        self, conn_id: str, method: str, target: str, is_write: Optional[bool] = None, actor: str = "agent"
    ) -> Tuple[bool, str]:
        """Enforces Global Lockdown, PROD Write Guardrail, and macOS Native Permission Gate."""
        settings = self.load_settings()
        if settings.get("global_lockdown", False):
            msg = "Blocked by irfHASH Global Kill Switch (Lockdown Active)"
            self.log_audit("ACCESS_REQUEST", conn_id, "DENIED_LOCKDOWN", msg, method=method, target=target, actor=actor)
            return False, msg

        catalog = self.load_catalog()
        entry = catalog.get("connections", {}).get(conn_id)
        if not entry:
            return False, f"Connection '{conn_id}' not found in irfHASH catalog"

        mode = entry.get("permission_mode", "ALLOW_READ_ASK_WRITE")
        if mode == "LOCKED":
            msg = f"Connection '{entry.get('name')}' is LOCKED by user policy"
            self.log_audit("ACCESS_REQUEST", conn_id, "DENIED_LOCKED", msg, method=method, target=target, actor=actor)
            return False, msg

        method_u = method.upper()
        if is_write is None:
            if method_u in ("GET", "HEAD", "OPTIONS"):
                is_write = False
            elif method_u == "POST" and any(
                target.endswith(sfx) or (sfx + "?") in target
                for sfx in ("/_search", "/_count", "/_msearch", "/_resolve/index", "/_field_caps", "/documents/search")
            ):
                is_write = False
            else:
                is_write = True

        if (entry.get("environment") == "PROD" or entry.get("prod_write_lock")) and is_write:
            msg = (
                f"BLOCKED BY irfHASH PROD WRITE GUARDRAIL: '{entry.get('name')}' is tagged PROD. "
                f"Write/mutation operation ({method_u} {target}) is strictly forbidden."
            )
            self.log_audit(
                "ACCESS_REQUEST", conn_id, "DENIED_PROD_GUARDRAIL", msg, method=method_u, target=target, actor=actor
            )
            return False, msg

        leases = {}
        if os.path.exists(LEASES_PATH):
            try:
                leases = json.load(open(LEASES_PATH, "r"))
            except Exception:
                leases = {}
        lease_exp = leases.get(conn_id, 0)
        now_ts = time.time()

        needs_prompt = False
        if mode == "ASK_EVERY_TIME":
            needs_prompt = True
        elif mode == "SESSION_15M" and now_ts > lease_exp:
            needs_prompt = True
        elif mode == "ALLOW_READ_ASK_WRITE" and is_write and now_ts > lease_exp:
            needs_prompt = True

        if needs_prompt and os.path.exists("/usr/bin/osascript"):
            approved, lease_granted = self._prompt_macos_user(entry, method_u, target, is_write)
            if not approved:
                msg = f"User denied access to '{entry.get('name')}' via macOS security prompt"
                self.log_audit("ACCESS_REQUEST", conn_id, "DENIED_BY_USER", msg, method=method_u, target=target, actor=actor)
                return False, msg
            if lease_granted:
                leases[conn_id] = now_ts + (settings.get("session_lease_minutes", 15) * 60)
                self._save_json_atomic(LEASES_PATH, leases)

        return True, "Authorized"

    def _prompt_macos_user(self, entry: Dict[str, Any], method: str, target: str, is_write: bool) -> Tuple[bool, bool]:
        op_label = "WRITE / MUTATION" if is_write else "READ"
        name = entry.get("name", entry["id"]).replace('"', "'")
        env = entry.get("environment", "TEST")
        short_target = target[:80].replace('"', "'")

        script = (
            f'display dialog "irfHASH Agentic Security Gate\\n\\n'
            f'System: {name} [{env}]\\n'
            f'Operation: {method} ({op_label})\\n'
            f'Target: {short_target}\\n\\n'
            f'Do you authorize the AI agent to use this encrypted credential?" '
            f'with title "irfHASH Security Approval" '
            f'buttons {{"Deny", "Allow 15m", "Allow Once"}} default button "Allow Once" cancel button "Deny" '
            f'with icon caution giving up after 120'
        )
        proc = subprocess.run(["/usr/bin/osascript", "-e", script], capture_output=True, text=True)
        if proc.returncode != 0 or "gave up:true" in proc.stdout:
            return False, False
        if "Allow 15m" in proc.stdout:
            return True, True
        if "Allow Once" in proc.stdout:
            return True, False
        return False, False

    def build_auth_headers(self, conn_id: str) -> Dict[str, str]:
        catalog = self.load_catalog()
        entry = catalog.get("connections", {}).get(conn_id)
        if not entry:
            raise KeyError(f"Connection '{conn_id}' not found")
        sec_obj = self._get_secret_obj(conn_id)
        secret_val = sec_obj.get("secret", "")
        extra_sec = sec_obj.get("extra", {})

        headers: Dict[str, str] = {}
        if entry.get("extra_headers"):
            headers.update(entry["extra_headers"])

        auth_type = entry.get("auth_type", "ApiKey")
        h_name = entry.get("header_name", "Authorization")
        h_prefix = entry.get("header_prefix", "")

        if auth_type == "Basic":
            user = extra_sec.get("username", os.environ.get("USER", "user"))
            raw_pair = secret_val if ":" in secret_val else f"{user}:{secret_val}"
            token = base64.b64encode(raw_pair.encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
        elif auth_type in ("ApiKey", "Bearer", "CustomHeader"):
            if secret_val:
                headers[h_name] = f"{h_prefix}{secret_val}"
        return headers

    def execute_http_request(
        self,
        conn_id: str,
        method: str,
        path_or_url: str,
        body: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        timeout: int = 25,
        actor: str = "agent",
    ) -> Dict[str, Any]:
        catalog = self.load_catalog()
        entry = catalog.get("connections", {}).get(conn_id)
        if not entry:
            raise KeyError(f"Connection '{conn_id}' not found")

        base_url = entry.get("url", "").rstrip("/")
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            full_url = path_or_url
        else:
            path_part = path_or_url if path_or_url.startswith("/") else "/" + path_or_url
            full_url = base_url + path_part

        allowed, reason = self.check_and_authorize(conn_id, method, full_url, actor=actor)
        if not allowed:
            return {"ok": False, "status": 403, "error": reason, "body": ""}

        headers = self.build_auth_headers(conn_id)
        headers.setdefault("Accept", "application/json")
        if body is not None and "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)

        data_bytes = body.encode("utf-8") if body is not None else None
        req = urllib.request.Request(full_url, data=data_bytes, headers=headers, method=method.upper())
        ctx = ssl.create_default_context()

        t0 = time.time()
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                status_code = resp.getcode()
                raw_body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            status_code = e.code
            raw_body = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
        except Exception as e:
            latency_ms = int((time.time() - t0) * 1000)
            err_str = self.scrub_output(str(e))
            self.log_audit(
                "HTTP_REQUEST",
                conn_id,
                "ERROR",
                f"{err_str} ({latency_ms}ms)",
                method=method.upper(),
                target=full_url,
                actor=actor,
            )
            return {"ok": False, "status": 0, "error": err_str, "body": ""}

        latency_ms = int((time.time() - t0) * 1000)
        scrubbed_body = self.scrub_output(raw_body)

        with _VAULT_LOCK:
            cat_latest = self.load_catalog()
            if conn_id in cat_latest.get("connections", {}):
                cat_latest["connections"][conn_id]["last_used_at"] = _now_iso()
                cat_latest["connections"][conn_id]["use_count"] = (
                    cat_latest["connections"][conn_id].get("use_count", 0) + 1
                )
                self.save_catalog(cat_latest)

        self.log_audit(
            "HTTP_REQUEST",
            conn_id,
            "ALLOWED",
            f"HTTP {status_code} ({latency_ms}ms)",
            method=method.upper(),
            target=full_url,
            actor=actor,
        )
        return {
            "ok": 200 <= status_code < 300,
            "status": status_code,
            "latency_ms": latency_ms,
            "body": scrubbed_body,
        }

    def verify_connection(self, conn_id: str, timeout: int = 10, actor: str = "verifier") -> Dict[str, Any]:
        """Runs a strictly read-only GET probe to check whether a credential is ACTIVE or EXPIRED."""
        catalog = self.load_catalog()
        entry = catalog.get("connections", {}).get(conn_id)
        if not entry:
            raise KeyError(f"Connection '{conn_id}' not found")

        system = entry.get("system", "").lower()
        base_url = entry.get("url", "").rstrip("/")
        auth_type = entry.get("auth_type", "")

        if auth_type == "PluginOAuth":
            with _VAULT_LOCK:
                cat_latest = self.load_catalog()
                ent = cat_latest.get("connections", {}).get(conn_id, entry)
                ent["status"] = "ACTIVE"
                ent["status_detail"] = "Connected via Plugin OAuth2"
                ent["last_verified_at"] = _now_iso()
                cat_latest.setdefault("connections", {})[conn_id] = ent
                self.save_catalog(cat_latest)
                return ent

        if auth_type == "OAuth2Client":
            sec_obj = self._get_secret_obj(conn_id)
            extra = sec_obj.get("extra", {})
            has_sec = bool(sec_obj.get("secret") or extra.get("client_secret") or extra.get("refresh_token"))
            with _VAULT_LOCK:
                cat_latest = self.load_catalog()
                ent = cat_latest.get("connections", {}).get(conn_id, entry)
                ent["status"] = "CONFIGURED" if has_sec else "EXPIRED"
                ent["status_detail"] = "OAuth2 Client/Token credentials encrypted in vault"
                ent["last_verified_at"] = _now_iso()
                cat_latest.setdefault("connections", {})[conn_id] = ent
                self.save_catalog(cat_latest)
                return ent

        probe_url = base_url
        if system == "search-cluster" or ".kb." in base_url:
            parsed = urllib.parse.urlparse(base_url)
            root_kb = f"{parsed.scheme}://{parsed.netloc}"
            probe_url = f"{root_kb}/api/actions/connectors"
        elif system == "search-engine" or ".es." in base_url:
            probe_url = f"{base_url}/_security/_authenticate"
        elif system == "jira":
            probe_url = f"{base_url}/rest/api/2/myself"
        elif system == "slack" or "slack.com" in base_url:
            probe_url = "https://slack.com/api/auth.test"
        elif system == "github":
            probe_url = "https://api.github.com/user"
        elif system == "gitlab":
            probe_url = f"{base_url}/user"
        elif system == "openai":
            probe_url = "https://api.openai.com/v1/models"
        elif system == "langsmith":
            probe_url = f"{base_url}/api/v1/info"
        elif system == "jina":
            probe_url = "https://r.jina.ai/https://example.com"

        headers = self.build_auth_headers(conn_id)
        headers.setdefault("Accept", "application/json")
        if system == "search-cluster" or ".kb." in base_url:
            headers["kbn-xsrf"] = "true"
        if system == "diagram-api":
            headers["X-Api-Version"] = "1"
        if system == "github":
            headers["User-Agent"] = "irfHASH-Verifier/1.0"

        req = urllib.request.Request(probe_url, headers=headers, method="GET")
        ctx = ssl.create_default_context()
        new_status = "UNVERIFIED"
        new_detail = ""
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                code = resp.getcode()
                body_sample = resp.read(400).decode("utf-8", errors="ignore")
                if system == "slack" and '"ok":false' in body_sample:
                    new_status = "EXPIRED"
                    new_detail = "Slack auth.test returned ok:false"
                else:
                    new_status = "ACTIVE"
                    new_detail = f"HTTP {code} OK"
        except urllib.error.HTTPError as e:
            code = e.code
            if code in (401, 403):
                new_status = "EXPIRED"
                new_detail = f"HTTP {code} Unauthorized / Expired Key"
            else:
                new_status = "EXPIRED" if code < 500 else "UNVERIFIED"
                new_detail = f"HTTP {code} ({e.reason})"
        except Exception as e:
            err_short = self.scrub_output(str(e))[:90]
            new_status = "UNVERIFIED"
            new_detail = f"Connection check: {err_short}"

        with _VAULT_LOCK:
            cat_latest = self.load_catalog()
            ent = cat_latest.get("connections", {}).get(conn_id, entry)
            ent["status"] = new_status
            ent["status_detail"] = new_detail
            ent["last_verified_at"] = _now_iso()
            cat_latest.setdefault("connections", {})[conn_id] = ent
            self.save_catalog(cat_latest)
            self.log_audit(
                "VERIFY_CONNECTION",
                conn_id,
                new_status,
                new_detail,
                method="GET",
                target=self.scrub_output(probe_url),
                actor=actor,
            )
            return ent

    def sanitize_chats(
        self, dry_run: bool = False, custom_dirs: Optional[List[str]] = None, actor: str = "sanitizer"
    ) -> Dict[str, Any]:
        """
        Scans AI chat transcripts and agent session files for any raw secrets stored in irfHASH.
        Replaces raw secrets with an AI-readable marker telling future agents the secret is
        redacted and available via 'irfhash request <id>' or 'irfhash exec <id>'.
        """
        catalog = self.load_catalog().get("connections", {})
        vault = self._load_encrypted_vault()

        replacements: List[Tuple[str, str, str]] = []
        for cid, sec_obj in vault.items():
            meta = catalog.get(cid, {})
            sys_name = meta.get("system", "api")
            env_name = meta.get("environment", "TEST")
            marker = (
                f"[REDACTED_BY_IRFHASH:id={cid}|system={sys_name}|env={env_name}|"
                f"note=Secret secured in local irfHASH vault. AI agents: run 'irfhash request {cid} <METHOD> <path>' "
                f"or 'irfhash exec {cid} <ENV_VAR> <cmd>' to use without exposing credentials]"
            )
            candidates = []
            main_sec = sec_obj.get("secret", "")
            if isinstance(main_sec, str) and len(main_sec) >= 16 and not main_sec.startswith(("oauth2:", "gcloud:")):
                candidates.append(main_sec)
            extra = sec_obj.get("extra", {})
            if isinstance(extra, dict):
                for k, ev in extra.items():
                    if k in ("client_secret", "refresh_token", "access_token") and isinstance(ev, str) and len(ev) >= 16:
                        candidates.append(ev)
            for c in candidates:
                replacements.append((c, marker, cid))

        replacements.sort(key=lambda x: len(x[0]), reverse=True)

        home = os.path.expanduser("~")
        target_roots = custom_dirs if custom_dirs else [
            os.path.join(home, ".gemini", "antigravity", "brain"),
            os.path.join(home, ".claude", "projects"),
            os.path.join(home, ".claude", "sessions"),
            os.path.join(home, ".codex", "sessions"),
            os.path.join(home, ".codex", "memories"),
        ]

        files_scanned = 0
        files_modified = 0
        total_redactions = 0
        affected_connections: Dict[str, int] = {}

        for root_dir in target_roots:
            if not os.path.exists(root_dir):
                continue
            for dirpath, dirnames, filenames in os.walk(root_dir):
                dirnames[:] = [
                    d for d in dirnames if d not in (".git", "node_modules", ".venv", "venv", "__pycache__", "irfhash")
                ]
                for fn in filenames:
                    if not fn.endswith((".jsonl", ".json", ".md", ".txt", ".log", ".py", ".sh", ".yaml", ".yml")):
                        continue
                    fp = os.path.join(dirpath, fn)
                    if os.path.abspath(fp).startswith(BASE_DIR):
                        continue
                    try:
                        if os.path.getsize(fp) > 50 * 1024 * 1024:
                            continue
                        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                    except Exception:
                        continue

                    files_scanned += 1
                    new_content = content
                    file_redactions = 0

                    for sec_str, marker, cid in replacements:
                        if sec_str in new_content:
                            cnt = new_content.count(sec_str)
                            if cnt > 0:
                                new_content = new_content.replace(sec_str, marker)
                                file_redactions += cnt
                                total_redactions += cnt
                                affected_connections[cid] = affected_connections.get(cid, 0) + cnt

                    if file_redactions > 0:
                        files_modified += 1
                        if not dry_run:
                            try:
                                with open(fp, "w", encoding="utf-8") as wf:
                                    wf.write(new_content)
                            except Exception:
                                pass

        mode_label = "DRY_RUN" if dry_run else "REDACTED"
        self.log_audit(
            "SANITIZE_CHATS",
            "ALL",
            mode_label,
            f"Scanned {files_scanned} files, {mode_label.lower()} {total_redactions} secrets across {files_modified} files",
            actor=actor,
        )
        return {
            "dry_run": dry_run,
            "files_scanned": files_scanned,
            "files_with_secrets": files_modified,
            "total_redactions": total_redactions,
            "affected_connections": affected_connections,
        }

    def configure_custom_domain(self, domain: str, map_etc_hosts: bool = False, port: int = 8765) -> Dict[str, Any]:
        """Configures a custom local bookmarkable domain name (e.g. 'irfhash.localhost' or 'irfhash.vault')."""
        clean = domain.strip().lower()
        clean = clean.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0].strip()
        if not clean:
            clean = "irfhash.localhost"

        settings = self.load_settings()
        settings["custom_domain"] = clean
        settings["dashboard_port"] = port
        self.save_settings(settings)

        hosts_mapped = False
        hosts_msg = ""
        try:
            hosts_txt = open("/etc/hosts", "r", encoding="utf-8", errors="ignore").read()
            if re.search(rf"^\s*127\.0\.0\.1\s+.*\b{re.escape(clean)}\b", hosts_txt, re.M):
                hosts_mapped = True
                hosts_msg = f"'{clean}' is mapped in /etc/hosts"
        except Exception:
            pass

        if clean.endswith(".localhost") or clean in ("localhost", "127.0.0.1"):
            hosts_mapped = True
            hosts_msg = f"'{clean}' resolves to 127.0.0.1 automatically via RFC 6761 (.localhost)"
        elif map_etc_hosts and not hosts_mapped and os.path.exists("/usr/bin/osascript"):
            cmd = f"echo '127.0.0.1 {clean}' >> /etc/hosts && dscacheutil -flushcache"
            osa = f'do shell script "{cmd}" with administrator privileges'
            proc = subprocess.run(["/usr/bin/osascript", "-e", osa], capture_output=True, text=True)
            if proc.returncode == 0:
                hosts_mapped = True
                hosts_msg = f"Mapped '127.0.0.1 {clean}' in /etc/hosts and flushed DNS cache"
            else:
                hosts_msg = (
                    f"Saved '{clean}'. To use without /etc/hosts prompt, use '{clean}.localhost' "
                    f"or run: sudo sh -c \"echo '127.0.0.1 {clean}' >> /etc/hosts\""
                )

        self.log_audit("CONFIGURE_DOMAIN", "GLOBAL", "ALLOWED", f"Domain: http://{clean}:{port} ({hosts_msg})", actor="user")
        return {
            "custom_domain": clean,
            "url": f"http://{clean}:{port}",
            "fallback_localhost_url": f"http://{clean if clean.endswith('.localhost') else clean + '.localhost'}:{port}",
            "hosts_mapped": hosts_mapped,
            "message": hosts_msg,
        }
