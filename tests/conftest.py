import pytest

from lockbox.crypto import KdfParams
from lockbox.vault import Entry, Vault

PASSWORD = "correct horse battery staple"


def fast_kdf():
    # Low cost so the test suite runs in seconds; never use these values for real.
    return KdfParams.new(time_cost=1, memory_cost=1024, parallelism=1)


@pytest.fixture()
def vault(tmp_path):
    v = Vault.create(tmp_path / "vault.json", PASSWORD, fast_kdf())
    v.add(Entry(name="github", password="Xq7!pL2#vR9@mK4$", username="alawi", tags=["dev"]))
    v.add(Entry(name="mail", password="another-Long-passphrase-2026", username="alawi@example.com"))
    return v
