"""Cryptographic core of Lockbox.

Design (envelope encryption, as in 1Password, Bitwarden or LUKS):

    master password ──Argon2id(salt, params)──► KEK  (key-encryption key, never stored)
    random 256-bit DEK (data-encryption key) ──AES-256-GCM(KEK)──► wrapped DEK  (stored)
    vault entries (JSON) ──AES-256-GCM(DEK)──► ciphertext                       (stored)

Why two keys: changing the master password only re-wraps the 32-byte DEK, and
the DEK itself never depends on the password's quality.

Every AES-GCM operation:
  * uses a fresh random 96-bit nonce (never reused with the same key);
  * authenticates the file header (format, version, KDF parameters) as
    associated data, so an attacker cannot lower the Argon2 cost or swap the
    salt without decryption failing.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict, dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
NONCE_BYTES = 12
SALT_BYTES = 16


class DecryptionError(Exception):
    """Wrong master password, or the file was modified or corrupted."""


@dataclass(frozen=True)
class KdfParams:
    """Argon2id parameters. Defaults follow OWASP guidance for interactive use
    (memory-hard: 64 MiB, 3 passes); they are stored in the vault header so
    they can be raised later without breaking old vaults."""

    time_cost: int = 3
    memory_cost: int = 64 * 1024   # KiB
    parallelism: int = 4
    salt: str = ""                 # base64

    @classmethod
    def new(cls, **overrides) -> "KdfParams":
        return cls(salt=b64e(os.urandom(SALT_BYTES)), **overrides)

    def to_dict(self) -> dict:
        return {"name": "argon2id", **asdict(self)}

    @classmethod
    def from_dict(cls, d: dict) -> "KdfParams":
        if d.get("name") != "argon2id":
            raise ValueError(f"unsupported KDF: {d.get('name')}")
        return cls(time_cost=int(d["time_cost"]), memory_cost=int(d["memory_cost"]),
                   parallelism=int(d["parallelism"]), salt=d["salt"])


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def derive_kek(password: str, params: KdfParams) -> bytes:
    if not password:
        raise ValueError("the master password cannot be empty")
    return hash_secret_raw(
        secret=password.encode("utf-8"), salt=b64d(params.salt),
        time_cost=params.time_cost, memory_cost=params.memory_cost,
        parallelism=params.parallelism, hash_len=KEY_BYTES, type=Type.ID,
    )


def canonical(obj: dict) -> bytes:
    """Deterministic JSON used as associated data."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def seal(key: bytes, plaintext: bytes, aad: bytes) -> dict:
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {"nonce": b64e(nonce), "ciphertext": b64e(ct)}


def open_sealed(key: bytes, box: dict, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(b64d(box["nonce"]), b64d(box["ciphertext"]), aad)
    except (InvalidTag, KeyError, ValueError) as exc:
        raise DecryptionError("wrong master password, or the vault file was modified") from exc


def new_data_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)
