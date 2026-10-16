import json
import os
import stat

import pytest

from conftest import PASSWORD, fast_kdf
from lockbox.crypto import DecryptionError, KdfParams, b64d, b64e
from lockbox.vault import Entry, Vault, VaultError


def test_roundtrip(vault):
    reopened = Vault.open(vault.path, PASSWORD)
    assert reopened.get("github").password == "Xq7!pL2#vR9@mK4$"
    assert reopened.get("mail").username == "alawi@example.com"


def test_file_contains_no_plaintext(vault):
    raw = vault.path.read_text()
    for secret in ("Xq7!pL2#vR9@mK4$", "github", "alawi", "passphrase"):
        assert secret not in raw


def test_wrong_password_rejected(vault):
    with pytest.raises(DecryptionError):
        Vault.open(vault.path, "wrong password")


def _tamper(path, mutate):
    doc = json.loads(path.read_text())
    mutate(doc)
    path.write_text(json.dumps(doc))


def test_modified_ciphertext_detected(vault):
    def flip(doc):
        ct = bytearray(b64d(doc["data"]["ciphertext"]))
        ct[5] ^= 0x01
        doc["data"]["ciphertext"] = b64e(bytes(ct))
    _tamper(vault.path, flip)
    with pytest.raises(DecryptionError):
        Vault.open(vault.path, PASSWORD)


def test_downgraded_kdf_parameters_detected(vault):
    # An attacker lowering the Argon2 cost (to speed up cracking) must break decryption
    _tamper(vault.path, lambda d: d["kdf"].update(time_cost=d["kdf"]["time_cost"] + 1))
    with pytest.raises(DecryptionError):
        Vault.open(vault.path, PASSWORD)


def test_swapped_data_block_detected(tmp_path, vault):
    other = Vault.create(tmp_path / "other.json", PASSWORD, fast_kdf())
    other_doc = json.loads(other.path.read_text())
    _tamper(vault.path, lambda d: d.update(data=other_doc["data"]))
    with pytest.raises(DecryptionError):
        Vault.open(vault.path, PASSWORD)


def test_fresh_nonces_on_every_save(vault):
    nonces = set()
    for i in range(5):
        vault.update("github", notes=f"edit {i}")
        doc = json.loads(vault.path.read_text())
        nonces.add(doc["data"]["nonce"])
        nonces.add(doc["key"]["nonce"])
    assert len(nonces) == 10


def test_change_password(vault):
    dek_before = vault._dek
    vault.change_password("a brand new master passphrase", kdf=fast_kdf())
    assert vault._dek == dek_before          # only re-wrapped
    with pytest.raises(DecryptionError):
        Vault.open(vault.path, PASSWORD)
    assert Vault.open(vault.path, "a brand new master passphrase").get("github")


def test_change_password_with_key_rotation(vault):
    dek_before = vault._dek
    vault.change_password("rotated passphrase here", kdf=fast_kdf(), rotate_data_key=True)
    assert vault._dek != dek_before
    assert Vault.open(vault.path, "rotated passphrase here").get("mail")


def test_file_permissions_and_no_temp_files(vault):
    mode = stat.S_IMODE(os.stat(vault.path).st_mode)
    assert mode == 0o600
    assert [p.name for p in vault.path.parent.iterdir()] == ["vault.json"]


def test_entry_management(vault):
    with pytest.raises(VaultError):
        vault.add(Entry(name="github", password="x"))
    vault.update("github", url="https://github.com", tags=["dev", "work"])
    assert vault.search("git")[0].url == "https://github.com"
    assert [e.name for e in vault.search(tag="work")] == ["github"]
    vault.remove("mail")
    with pytest.raises(VaultError):
        Vault.open(vault.path, PASSWORD).get("mail")


def test_unicode_password_and_entries(tmp_path):
    v = Vault.create(tmp_path / "u.json", "كلمة سر طويلة جدا", fast_kdf())
    v.add(Entry(name="banque", password="mötdepässe-مغرب-2026", notes="café"))
    assert Vault.open(tmp_path / "u.json", "كلمة سر طويلة جدا").get("banque").notes == "café"


def test_create_refuses_to_overwrite(vault):
    with pytest.raises(VaultError):
        Vault.create(vault.path, PASSWORD, fast_kdf())


def test_not_a_vault(tmp_path):
    p = tmp_path / "x.json"
    p.write_text('{"hello": 1}')
    with pytest.raises(VaultError):
        Vault.open(p, PASSWORD)


def test_empty_master_password_refused(tmp_path):
    with pytest.raises(ValueError):
        Vault.create(tmp_path / "e.json", "", fast_kdf())


def test_default_kdf_meets_owasp():
    k = KdfParams.new()
    assert k.memory_cost >= 19 * 1024 and k.time_cost >= 2
