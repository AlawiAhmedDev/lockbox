"""The vault file and its entries.

File layout (JSON, so it can be inspected; only the secrets are encrypted)::

    {
      "format": "lockbox", "version": 1,
      "kdf":   {"name": "argon2id", "time_cost": 3, "memory_cost": 65536,
                "parallelism": 4, "salt": "..."},
      "key":   {"nonce": "...", "ciphertext": "..."},   # DEK wrapped by the KEK
      "data":  {"nonce": "...", "ciphertext": "..."}    # entries encrypted by the DEK
    }

Writes are atomic (temporary file + rename) and the file is created with
owner-only permissions, so a crash mid-save never leaves a half-written vault.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import crypto
from .crypto import DecryptionError, KdfParams

FORMAT = "lockbox"
VERSION = 1


class VaultError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Entry:
    name: str
    password: str
    username: str = ""
    url: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    created: str = field(default_factory=_now)
    updated: str = field(default_factory=_now)

    def public(self) -> dict:
        """Everything except the password, for listings."""
        d = asdict(self)
        d.pop("password")
        return d


class Vault:
    def __init__(self, path: Path, kdf: KdfParams, kek: bytes, dek: bytes,
                 entries: dict[str, Entry]):
        self.path = Path(path)
        self._kdf = kdf
        self._kek = kek
        self._dek = dek
        self.entries = entries

    # --- lifecycle --------------------------------------------------------

    @classmethod
    def create(cls, path: str | Path, password: str, kdf: KdfParams | None = None) -> "Vault":
        path = Path(path)
        if path.exists():
            raise VaultError(f"{path} already exists")
        kdf = kdf or KdfParams.new()
        vault = cls(path, kdf, crypto.derive_kek(password, kdf), crypto.new_data_key(), {})
        vault.save()
        return vault

    @classmethod
    def open(cls, path: str | Path, password: str) -> "Vault":
        path = Path(path)
        if not path.exists():
            raise VaultError(f"no vault at {path}; create one with 'lockbox init'")
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            if doc.get("format") != FORMAT:
                raise VaultError(f"{path} is not a Lockbox vault")
            if doc.get("version") != VERSION:
                raise VaultError(f"unsupported vault version {doc.get('version')}")
            kdf = KdfParams.from_dict(doc["kdf"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise VaultError(f"{path} is damaged: {exc}") from exc

        aad = cls._aad(kdf)
        kek = crypto.derive_kek(password, kdf)
        dek = crypto.open_sealed(kek, doc.get("key", {}), aad)
        plaintext = crypto.open_sealed(dek, doc.get("data", {}), aad)
        entries = {e["name"]: Entry(**e) for e in json.loads(plaintext)["entries"]}
        return cls(path, kdf, kek, dek, entries)

    @staticmethod
    def _aad(kdf: KdfParams) -> bytes:
        return crypto.canonical({"format": FORMAT, "version": VERSION, "kdf": kdf.to_dict()})

    def save(self) -> None:
        aad = self._aad(self._kdf)
        payload = json.dumps({"entries": [asdict(e) for e in self.entries.values()]},
                             ensure_ascii=False).encode("utf-8")
        doc = {
            "format": FORMAT, "version": VERSION, "kdf": self._kdf.to_dict(),
            "key": crypto.seal(self._kek, self._dek, aad),
            "data": crypto.seal(self._dek, payload, aad),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".lockbox-", dir=self.path.parent)
        try:
            os.chmod(tmp, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def change_password(self, new_password: str, kdf: KdfParams | None = None,
                        rotate_data_key: bool = False) -> None:
        """New salt and KEK; the DEK is re-wrapped (or replaced if rotate_data_key)."""
        self._kdf = kdf or KdfParams.new(time_cost=self._kdf.time_cost,
                                         memory_cost=self._kdf.memory_cost,
                                         parallelism=self._kdf.parallelism)
        self._kek = crypto.derive_kek(new_password, self._kdf)
        if rotate_data_key:
            self._dek = crypto.new_data_key()
        self.save()

    # --- entries ----------------------------------------------------------

    def add(self, entry: Entry, overwrite: bool = False) -> Entry:
        if not entry.name.strip():
            raise VaultError("an entry needs a name")
        if entry.name in self.entries and not overwrite:
            raise VaultError(f"'{entry.name}' already exists (use 'edit' to change it)")
        self.entries[entry.name] = entry
        self.save()
        return entry

    def get(self, name: str) -> Entry:
        try:
            return self.entries[name]
        except KeyError:
            raise VaultError(f"no entry named '{name}'") from None

    def update(self, name: str, **changes) -> Entry:
        entry = self.get(name)
        for key, value in changes.items():
            if value is not None:
                setattr(entry, key, value)
        entry.updated = _now()
        self.save()
        return entry

    def remove(self, name: str) -> None:
        self.get(name)
        del self.entries[name]
        self.save()

    def search(self, text: str = "", tag: str | None = None) -> list[Entry]:
        text = text.lower()
        out = []
        for e in sorted(self.entries.values(), key=lambda e: e.name.lower()):
            haystack = " ".join([e.name, e.username, e.url, e.notes, *e.tags]).lower()
            if text in haystack and (tag is None or tag in e.tags):
                out.append(e)
        return out


__all__ = ["Vault", "Entry", "VaultError", "DecryptionError", "KdfParams"]
