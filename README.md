# Lockbox

[![CI](https://github.com/AlawiAhmedDev/lockbox/actions/workflows/ci.yml/badge.svg)](https://github.com/AlawiAhmedDev/lockbox/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Crypto](https://img.shields.io/badge/crypto-Argon2id%20%2B%20AES--256--GCM-6f42c1)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

**A command-line password vault built on Argon2id and AES-256-GCM, with envelope encryption, an authenticated header and a password health audit.**

*[Version française](README.fr.md)*

```text
$ lockbox init
Master password:
Repeat master password:
Vault created at /home/alawi/.lockbox/vault.json

$ lockbox add github --username alawi --url https://github.com --generate
Master password:
Saved 'github' with a generated password

$ lockbox get github --clip
Master password:
Password for 'github' copied to the clipboard (clip.exe). Clear it after use.

$ lockbox audit
Master password:
bank
  - very common password
  - short (9 characters, aim for 12+)
  - reused in forum
forum
  - very common password
  - short (9 characters, aim for 12+)
  - reused in bank

2 of 3 entries need attention. Fix them with: lockbox edit NAME --generate
```

## How the encryption works

```
 master password ──► Argon2id (random salt, 64 MiB, 3 passes) ──► KEK   never stored
                                                                    │
 random 256-bit DEK ─────────── AES-256-GCM(KEK) ──────────────► wrapped DEK  ┐
 entries (JSON) ─────────────── AES-256-GCM(DEK) ──────────────► ciphertext   ├─ vault.json
 header {format, version, KDF parameters, salt} ── authenticated by both ──────┘
```

| Choice | Why |
|---|---|
| **Argon2id** to derive the key | Memory-hard: each guess of the master password costs 64 MiB of RAM and about 130 ms, which makes GPU and ASIC cracking expensive. Winner of the Password Hashing Competition, recommended by OWASP. |
| **Envelope encryption** (KEK wraps a random DEK) | Changing the master password re-wraps 32 bytes instead of re-encrypting everything, and the data key never depends on the password's quality. `lockbox passwd --rotate-key` also replaces the DEK. Same design as 1Password, Bitwarden or LUKS. |
| **AES-256-GCM** | Authenticated encryption: any modified byte makes decryption fail instead of returning corrupted data. |
| **Fresh 96-bit random nonce on every save** | A GCM nonce must never repeat under the same key. A test checks this. |
| **Header as associated data** | An attacker who lowers the Argon2 cost in the file to speed up cracking, or swaps the salt or the data block, breaks decryption. Tests check all three. |
| **Atomic writes, `0600` permissions** | Writes go to a temporary file followed by `fsync` and a rename, so a crash never leaves a half-written vault. Only the owner can read the file. |
| **`secrets` module** for generation | Cryptographically secure RNG. Rejection sampling guarantees every selected character class while keeping the distribution uniform. |

The vault file is plain JSON: the structure is visible, but entries, names and usernames are not.

```json
{
  "format": "lockbox", "version": 1,
  "kdf":  {"name": "argon2id", "time_cost": 3, "memory_cost": 65536, "parallelism": 4, "salt": "ThAw4G..."},
  "key":  {"nonce": "sU5K8/vD...", "ciphertext": "ZkQtdbqB..."},
  "data": {"nonce": "G+zFtrVO...", "ciphertext": "vYHQTylW..."}
}
```

## Password audit

`lockbox audit` flags passwords that are:

- **common**, found on a list of the most frequent passwords in breaches;
- **short or low-entropy**, under 12 characters or about 60 bits;
- **reused** across entries;
- **based on the username or site name**;
- **old**, not changed for more than a year;
- **breached** (with `--online`), checked against [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) using **k-anonymity**: only the first 5 hex characters of the password's SHA-1 are sent, and the match against the returned suffixes is done locally. The service never sees the password or its full hash. A test asserts that exactly 5 characters leave the machine.

## Installation

```bash
git clone https://github.com/AlawiAhmedDev/lockbox.git
cd lockbox
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
lockbox init
```

## Commands

| Command | Does |
|---|---|
| `lockbox init` | Create a vault. Argon2 cost can be tuned with `--kdf-memory-mib`, `--kdf-time` and `--kdf-parallelism` |
| `lockbox add NAME [--username U] [--url URL] [--tag T] [--generate]` | Add an entry, typing or generating its password |
| `lockbox get NAME` | Print the password (pipe-friendly); `--clip` copies it, `--all` shows the whole entry |
| `lockbox list [TEXT] [--tag T] [--json]` | List or search entries; passwords are never shown |
| `lockbox edit NAME [--generate \| --password] [...]` | Change fields or rotate the password |
| `lockbox rm NAME [--yes]` | Delete an entry |
| `lockbox generate [--length N] [--count N] [--no-symbols] [--no-ambiguous]` | Generate passwords without saving them |
| `lockbox audit [--online] [--fail]` | Health report; `--fail` returns exit code 2 when issues are found |
| `lockbox passwd [--rotate-key]` | Change the master password |
| `lockbox info` | Show the encryption parameters (no password needed) |

The vault lives at `~/.lockbox/vault.json`, or wherever `--vault` or `$LOCKBOX_VAULT` points. `--password-stdin` reads passwords from standard input, for scripts and CI.

Exit codes: `0` success, `1` usage or vault error, `2` audit found issues (with `--fail`), `3` wrong master password or tampered file.

## Threat model

**Protects against**
- **Theft of the vault file**, for example from a backup, a cloud folder or a lost laptop. The attacker must brute-force Argon2id, which costs 64 MiB and about 130 ms per guess, with a unique salt per vault.
- **Tampering with the file.** Any change to the ciphertext, key or header is detected.
- **Leaking passwords during the breach check**, thanks to k-anonymity.

**Does not protect against**
- **A compromised computer.** Malware or a keylogger can capture the master password when it is typed.
- **A weak master password.** Argon2 slows guessing down but cannot save `azerty123`. Use a long passphrase.
- **Secrets left in memory.** Python cannot reliably erase strings from RAM.
- **The clipboard.** Other programs can read it, and Lockbox does not clear it automatically.

Lockbox is a learning project focused on getting the cryptography right. For real secrets, use an audited manager such as KeePassXC or Bitwarden.

## Tests

```bash
pip install -e ".[dev]"
pytest -v
```

27 tests. Beyond the round-trips, they cover the attacks the design is meant to stop:

- a wrong master password;
- a single flipped bit in the ciphertext;
- a lowered Argon2 cost in the header;
- the data block swapped from another vault;
- nonce reuse across saves;
- leftover temporary files and file permissions;
- password changes with and without key rotation;
- Unicode (Arabic) master passwords;
- the k-anonymity guarantee of the breach check.

CI runs them on Python 3.10 to 3.13. The test suite uses deliberately low Argon2 settings so it finishes in under a second.

## Project layout

```
lockbox/
├── lockbox/
│   ├── crypto.py      # Argon2id, AES-256-GCM, sealing with authenticated header
│   ├── vault.py       # file format, envelope encryption, atomic save, entries
│   ├── generator.py   # CSPRNG password generator, entropy
│   ├── audit.py       # weak / reused / old / breached checks, HIBP k-anonymity
│   └── cli.py         # command-line interface
└── tests/             # 27 pytest tests
```

## Roadmap

- [ ] Clear the clipboard automatically after 30 seconds
- [ ] TOTP (2FA code) generation for stored entries
- [ ] Encrypted export and import (KeePass CSV, Bitwarden JSON)
- [ ] Browser version with WebCrypto and Argon2 compiled to WebAssembly

## Author

**Alawi Masfar**, MSc in Artificial Intelligence and Cybersecurity. GitHub: [@AlawiAhmedDev](https://github.com/AlawiAhmedDev)

## License

[MIT](LICENSE)
