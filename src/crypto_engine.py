#!/usr/bin/env python3
"""
irfHASH Crypto Engine
Isolated Runtime Fortress: Hardened Agentic Secret Hub

Provides dual-layer hardware-backed security:
1. Master 256-bit key stored in macOS Keychain (Secure Enclave / Login Keychain).
2. In-memory AES-256-GCM authenticated encryption via OpenSSL libcrypto (ctypes),
   with per-record HKDF-SHA256 subkey derivation and AAD binding.
3. Per-secret synchronization into macOS Keychain.
"""

import base64
import ctypes
import getpass
import hashlib
import hmac
import json
import os
import secrets
import subprocess
from typing import Dict, Any

KEYCHAIN_MASTER_SERVICE = "io.irfhash.vault.master"
KEYCHAIN_ITEM_PREFIX = "io.irfhash.vault.secret."
KEYCHAIN_ACCOUNT = os.environ.get("USER") or getpass.getuser() or "local-user"

_LIBCRYPTO_PATHS = [
    "/opt/homebrew/lib/libcrypto.dylib",
    "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib",
    "/usr/local/opt/openssl@3/lib/libcrypto.dylib",
    "/usr/lib/libcrypto.dylib",
    "libcrypto.so.3",
    "libcrypto.so",
]

_libcrypto = None
for _p in _LIBCRYPTO_PATHS:
    try:
        if _p.startswith("/") and not os.path.exists(_p):
            continue
        _libcrypto = ctypes.CDLL(_p)
        break
    except Exception:
        pass

if _libcrypto is None:
    raise RuntimeError("Could not load OpenSSL libcrypto for AES-256-GCM encryption")

_libcrypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
_libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
_libcrypto.EVP_aes_256_gcm.restype = ctypes.c_void_p

_libcrypto.EVP_EncryptInit_ex.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p
]
_libcrypto.EVP_EncryptUpdate.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int
]
_libcrypto.EVP_EncryptFinal_ex.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)
]

_libcrypto.EVP_DecryptInit_ex.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p
]
_libcrypto.EVP_DecryptUpdate.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int
]
_libcrypto.EVP_DecryptFinal_ex.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)
]

_libcrypto.EVP_CIPHER_CTX_ctrl.argtypes = [
    ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p
]

EVP_CTRL_GCM_SET_IVLEN = 0x09
EVP_CTRL_GCM_GET_TAG = 0x10
EVP_CTRL_GCM_SET_TAG = 0x11


def _hkdf_sha256(master_key: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256 key derivation."""
    prk = hmac.new(salt, master_key, hashlib.sha256).digest()
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def aes_256_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Dict[str, str]:
    """Encrypts plaintext in-memory using AES-256-GCM with 96-bit random nonce and 128-bit tag."""
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = secrets.token_bytes(12)
    salt = secrets.token_bytes(16)
    derived_key = _hkdf_sha256(key, salt, b"irfhash-aes256gcm-v1:" + aad, 32)

    ctx = _libcrypto.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")
    try:
        cipher = _libcrypto.EVP_aes_256_gcm()
        if _libcrypto.EVP_EncryptInit_ex(ctx, cipher, None, None, None) != 1:
            raise RuntimeError("EVP_EncryptInit_ex cipher init failed")
        if _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(nonce), None) != 1:
            raise RuntimeError("EVP_CTRL_GCM_SET_IVLEN failed")
        if _libcrypto.EVP_EncryptInit_ex(ctx, None, None, derived_key, nonce) != 1:
            raise RuntimeError("EVP_EncryptInit_ex key/nonce failed")

        outlen = ctypes.c_int(0)
        if aad:
            if _libcrypto.EVP_EncryptUpdate(ctx, None, ctypes.byref(outlen), aad, len(aad)) != 1:
                raise RuntimeError("EVP_EncryptUpdate AAD failed")

        outbuf = ctypes.create_string_buffer(len(plaintext) + 16)
        if _libcrypto.EVP_EncryptUpdate(ctx, outbuf, ctypes.byref(outlen), plaintext, len(plaintext)) != 1:
            raise RuntimeError("EVP_EncryptUpdate plaintext failed")
        total_len = outlen.value

        final_len = ctypes.c_int(0)
        final_buf = ctypes.create_string_buffer(16)
        if _libcrypto.EVP_EncryptFinal_ex(ctx, final_buf, ctypes.byref(final_len)) != 1:
            raise RuntimeError("EVP_EncryptFinal_ex failed")
        ciphertext = outbuf.raw[:total_len] + final_buf.raw[:final_len.value]

        tag_buf = ctypes.create_string_buffer(16)
        if _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_buf) != 1:
            raise RuntimeError("EVP_CTRL_GCM_GET_TAG failed")

        return {
            "alg": "AES-256-GCM-HKDF-SHA256",
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "tag": base64.b64encode(tag_buf.raw[:16]).decode("ascii"),
            "ct": base64.b64encode(ciphertext).decode("ascii"),
        }
    finally:
        _libcrypto.EVP_CIPHER_CTX_free(ctx)


def aes_256_gcm_decrypt(key: bytes, envelope: Dict[str, str], aad: bytes = b"") -> bytes:
    """Decrypts and authenticates an AES-256-GCM envelope in-memory."""
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    salt = base64.b64decode(envelope["salt"])
    nonce = base64.b64decode(envelope["nonce"])
    tag = base64.b64decode(envelope["tag"])
    ciphertext = base64.b64decode(envelope["ct"])
    derived_key = _hkdf_sha256(key, salt, b"irfhash-aes256gcm-v1:" + aad, 32)

    ctx = _libcrypto.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")
    try:
        cipher = _libcrypto.EVP_aes_256_gcm()
        if _libcrypto.EVP_DecryptInit_ex(ctx, cipher, None, None, None) != 1:
            raise RuntimeError("EVP_DecryptInit_ex cipher init failed")
        if _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(nonce), None) != 1:
            raise RuntimeError("EVP_CTRL_GCM_SET_IVLEN failed")
        if _libcrypto.EVP_DecryptInit_ex(ctx, None, None, derived_key, nonce) != 1:
            raise RuntimeError("EVP_DecryptInit_ex key/nonce failed")

        outlen = ctypes.c_int(0)
        if aad:
            if _libcrypto.EVP_DecryptUpdate(ctx, None, ctypes.byref(outlen), aad, len(aad)) != 1:
                raise RuntimeError("EVP_DecryptUpdate AAD failed")

        outbuf = ctypes.create_string_buffer(len(ciphertext) + 16)
        if _libcrypto.EVP_DecryptUpdate(ctx, outbuf, ctypes.byref(outlen), ciphertext, len(ciphertext)) != 1:
            raise RuntimeError("EVP_DecryptUpdate ciphertext failed")
        total_len = outlen.value

        tag_buf = ctypes.create_string_buffer(tag, len(tag))
        if _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, len(tag), tag_buf) != 1:
            raise RuntimeError("EVP_CTRL_GCM_SET_TAG failed")

        final_len = ctypes.c_int(0)
        final_buf = ctypes.create_string_buffer(16)
        res = _libcrypto.EVP_DecryptFinal_ex(ctx, final_buf, ctypes.byref(final_len))
        if res != 1:
            raise ValueError("AES-256-GCM authentication tag verification failed! Vault tampered or wrong key.")

        return outbuf.raw[:total_len] + final_buf.raw[:final_len.value]
    finally:
        _libcrypto.EVP_CIPHER_CTX_free(ctx)


def get_or_create_master_key() -> bytes:
    """Fetches the 256-bit master key from macOS Keychain, creating it if not yet initialized."""
    if os.path.exists("/usr/bin/security"):
        proc = subprocess.run(
            ["/usr/bin/security", "find-generic-password", "-s", KEYCHAIN_MASTER_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            raw_b64 = proc.stdout.strip()
            try:
                key = base64.b64decode(raw_b64)
                if len(key) == 32:
                    return key
            except Exception:
                pass

        new_key = secrets.token_bytes(32)
        b64_key = base64.b64encode(new_key).decode("ascii")
        subprocess.run(
            [
                "/usr/bin/security",
                "add-generic-password",
                "-U",
                "-s", KEYCHAIN_MASTER_SERVICE,
                "-a", KEYCHAIN_ACCOUNT,
                "-l", "irfHASH Master Encryption Key (AES-256-GCM)",
                "-w", b64_key,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return new_key

    # Fallback local key file with 0600 permissions for non-macOS systems
    fallback_path = os.path.expanduser("~/.irfhash/.master.key")
    os.makedirs(os.path.dirname(fallback_path), mode=0o700, exist_ok=True)
    if os.path.exists(fallback_path):
        return base64.b64decode(open(fallback_path, "r").read().strip())
    new_key = secrets.token_bytes(32)
    with open(fallback_path, "w") as f:
        f.write(base64.b64encode(new_key).decode("ascii"))
    os.chmod(fallback_path, 0o600)
    return new_key


def store_secret_in_keychain(conn_id: str, secret_payload: Dict[str, Any]) -> bool:
    """Stores an individual encrypted envelope in macOS Keychain as secondary hardware-backed storage."""
    if not os.path.exists("/usr/bin/security"):
        return False
    master = get_or_create_master_key()
    plaintext = json.dumps(secret_payload, sort_keys=True).encode("utf-8")
    env = aes_256_gcm_encrypt(master, plaintext, aad=conn_id.encode("utf-8"))
    encoded = base64.b64encode(json.dumps(env).encode("utf-8")).decode("ascii")
    service = f"{KEYCHAIN_ITEM_PREFIX}{conn_id}"
    proc = subprocess.run(
        [
            "/usr/bin/security",
            "add-generic-password",
            "-U",
            "-s", service,
            "-a", KEYCHAIN_ACCOUNT,
            "-l", f"irfHASH Secret: {conn_id}",
            "-w", encoded,
        ],
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def delete_secret_from_keychain(conn_id: str) -> bool:
    """Removes a secret entry from macOS Keychain."""
    if not os.path.exists("/usr/bin/security"):
        return False
    service = f"{KEYCHAIN_ITEM_PREFIX}{conn_id}"
    proc = subprocess.run(
        ["/usr/bin/security", "delete-generic-password", "-s", service, "-a", KEYCHAIN_ACCOUNT],
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def mask_secret_preview(secret_str: str) -> str:
    """Creates a safe non-reversible masked preview so the user can recognize which key is stored."""
    if not secret_str:
        return "(none)"
    s = secret_str.strip()
    length = len(s)
    if length <= 8:
        return f"**** (len={length})"
    return f"{s[:3]}••••{s[-4:]} (len={length})"
