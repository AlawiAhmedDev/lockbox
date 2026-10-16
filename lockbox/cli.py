"""Command-line interface.

    lockbox init                         create a vault
    lockbox add github --username me --generate
    lockbox get github                   print the password (pipe-friendly)
    lockbox get github --clip            copy it to the clipboard instead
    lockbox list [text] [--tag work]
    lockbox edit github --generate       rotate a password
    lockbox rm github
    lockbox generate --length 24
    lockbox audit [--online]             weak / reused / old / breached passwords
    lockbox passwd [--rotate-key]        change the master password
    lockbox info                         show the vault's encryption parameters

The vault path comes from --vault, then $LOCKBOX_VAULT, then ~/.lockbox/vault.json.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__
from .audit import audit
from .crypto import DecryptionError, KdfParams
from .generator import SYMBOLS, entropy_bits, generate
from .vault import Entry, Vault, VaultError

OWASP_MIN_MEMORY_MIB = 19


def default_vault() -> Path:
    return Path(os.environ.get("LOCKBOX_VAULT", Path.home() / ".lockbox" / "vault.json"))


class Prompter:
    """Reads secrets from the terminal, or from stdin with --password-stdin (scripts, CI)."""

    def __init__(self, from_stdin: bool):
        self.from_stdin = from_stdin
        self._lines = iter(sys.stdin.read().splitlines()) if from_stdin else None

    def ask(self, prompt: str) -> str:
        if self.from_stdin:
            try:
                return next(self._lines)
            except StopIteration:
                raise SystemExit("error: not enough lines on stdin") from None
        return getpass.getpass(prompt)

    def new_password(self, what: str = "Master password") -> str:
        first = self.ask(f"{what}: ")
        if self.from_stdin:
            return first
        if first != self.ask(f"Repeat {what.lower()}: "):
            raise SystemExit("error: the two passwords do not match")
        return first


def _open(args, prompter: Prompter) -> Vault:
    return Vault.open(args.vault, prompter.ask("Master password: "))


def _gen_from(args) -> str:
    return generate(length=args.length, symbols=not args.no_symbols,
                    exclude_ambiguous=args.no_ambiguous)


def _copy_to_clipboard(text: str) -> str:
    for tool in (["clip.exe"], ["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"],
                 ["xsel", "--clipboard", "--input"]):
        if shutil.which(tool[0]):
            subprocess.run(tool, input=text.encode("utf-16le" if tool[0] == "clip.exe" else "utf-8"),
                           check=True)
            return tool[0]
    raise SystemExit("error: no clipboard tool found (clip.exe, pbcopy, wl-copy, xclip or xsel)")


# --- commands ----------------------------------------------------------------

def cmd_init(args, p: Prompter) -> int:
    if args.kdf_memory_mib < OWASP_MIN_MEMORY_MIB:
        print(f"warning: {args.kdf_memory_mib} MiB is below the OWASP minimum of "
              f"{OWASP_MIN_MEMORY_MIB} MiB for Argon2id", file=sys.stderr)
    password = p.new_password()
    if len(password) < 12:
        print("warning: a master password of 12+ characters (or a passphrase) is recommended",
              file=sys.stderr)
    kdf = KdfParams.new(time_cost=args.kdf_time, memory_cost=args.kdf_memory_mib * 1024,
                        parallelism=args.kdf_parallelism)
    Vault.create(args.vault, password, kdf)
    print(f"Vault created at {args.vault}")
    return 0


def cmd_add(args, p: Prompter) -> int:
    vault = _open(args, p)
    password = _gen_from(args) if args.generate else p.ask(f"Password for {args.name}: ")
    vault.add(Entry(name=args.name, password=password, username=args.username or "",
                    url=args.url or "", notes=args.notes or "", tags=args.tag or []))
    print(f"Saved '{args.name}'" + (" with a generated password" if args.generate else ""))
    return 0


def cmd_get(args, p: Prompter) -> int:
    entry = _open(args, p).get(args.name)
    if args.all:
        data = entry.public() | {"password": entry.password}
        print(json.dumps(data, indent=2, ensure_ascii=False))
    elif args.clip:
        tool = _copy_to_clipboard(entry.password)
        print(f"Password for '{entry.name}' copied to the clipboard ({tool}). "
              "Clear it after use.", file=sys.stderr)
    else:
        print(entry.password)
    return 0


def cmd_list(args, p: Prompter) -> int:
    entries = _open(args, p).search(args.text or "", args.tag)
    if args.json:
        print(json.dumps([e.public() for e in entries], indent=2, ensure_ascii=False))
        return 0
    if not entries:
        print("No entries." if not (args.text or args.tag) else "No matching entries.")
        return 0
    width = max(len(e.name) for e in entries)
    for e in entries:
        tags = f"  [{', '.join(e.tags)}]" if e.tags else ""
        print(f"{e.name.ljust(width)}  {e.username or '-'}  {e.url}{tags}")
    return 0


def cmd_edit(args, p: Prompter) -> int:
    vault = _open(args, p)
    new_password = None
    if args.generate:
        new_password = _gen_from(args)
    elif args.password:
        new_password = p.ask(f"New password for {args.name}: ")
    vault.update(args.name, password=new_password, username=args.username, url=args.url,
                 notes=args.notes, tags=args.tag)
    print(f"Updated '{args.name}'")
    return 0


def cmd_rm(args, p: Prompter) -> int:
    vault = _open(args, p)
    vault.get(args.name)
    if not args.yes:
        if p.from_stdin or input(f"Delete '{args.name}'? [y/N] ").strip().lower() != "y":
            print("Cancelled (use --yes to skip this question).")
            return 1
    vault.remove(args.name)
    print(f"Deleted '{args.name}'")
    return 0


def cmd_generate(args, p: Prompter) -> int:
    for _ in range(args.count):
        print(_gen_from(args))
    size = 26 * 2 + 10 + (0 if args.no_symbols else len(SYMBOLS))
    print(f"~{entropy_bits(args.length, size):.0f} bits of entropy each", file=sys.stderr)
    return 0


def cmd_audit(args, p: Prompter) -> int:
    vault = _open(args, p)
    if args.online:
        print("Checking breaches with Have I Been Pwned (only 5 characters of each "
              "password's SHA-1 are sent)...", file=sys.stderr)
    findings = audit(list(vault.entries.values()), check_breaches=args.online)
    total = len(vault.entries)
    if not findings:
        print(f"All {total} passwords look healthy.")
        return 0
    for f in findings:
        print(f"{f.entry}")
        for issue in f.issues:
            print(f"  - {issue}")
    print(f"\n{len(findings)} of {total} entries need attention. "
          "Fix them with: lockbox edit NAME --generate")
    return 2 if args.fail else 0


def cmd_passwd(args, p: Prompter) -> int:
    vault = _open(args, p)
    vault.change_password(p.new_password("New master password"), rotate_data_key=args.rotate_key)
    print("Master password changed" + (" and data key rotated" if args.rotate_key else ""))
    return 0


def cmd_info(args, p: Prompter) -> int:
    doc = json.loads(Path(args.vault).read_text(encoding="utf-8"))
    k = doc["kdf"]
    print(f"Vault:      {args.vault}")
    print(f"Format:     {doc['format']} v{doc['version']}")
    print(f"KDF:        {k['name']}, {k['memory_cost'] // 1024} MiB, {k['time_cost']} passes, "
          f"{k['parallelism']} lanes")
    print("Encryption: AES-256-GCM, random 96-bit nonce per write, header authenticated")
    print(f"Size:       {Path(args.vault).stat().st_size} bytes")
    return 0


# --- parser ------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lockbox", description="Encrypted password vault "
                                "(Argon2id + AES-256-GCM).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--vault", type=Path, default=None, help="vault file (default: $LOCKBOX_VAULT "
                   "or ~/.lockbox/vault.json)")
    p.add_argument("--password-stdin", action="store_true",
                   help="read the master password (and others) from stdin, one per line")
    sub = p.add_subparsers(dest="command", required=True)

    def gen_opts(sp):
        sp.add_argument("--length", type=int, default=20)
        sp.add_argument("--no-symbols", action="store_true")
        sp.add_argument("--no-ambiguous", action="store_true", help="avoid I, l, 1, O, 0...")

    s = sub.add_parser("init", help="create a new vault")
    s.add_argument("--kdf-time", type=int, default=3)
    s.add_argument("--kdf-memory-mib", type=int, default=64)
    s.add_argument("--kdf-parallelism", type=int, default=4)
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("add", help="add an entry")
    s.add_argument("name")
    s.add_argument("--username")
    s.add_argument("--url")
    s.add_argument("--notes")
    s.add_argument("--tag", action="append")
    s.add_argument("--generate", action="store_true", help="generate the password")
    gen_opts(s)
    s.set_defaults(func=cmd_add)

    s = sub.add_parser("get", help="print or copy a password")
    s.add_argument("name")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--clip", action="store_true", help="copy to the clipboard")
    g.add_argument("--all", action="store_true", help="show the whole entry as JSON")
    s.set_defaults(func=cmd_get)

    s = sub.add_parser("list", help="list or search entries (passwords are not shown)")
    s.add_argument("text", nargs="?")
    s.add_argument("--tag")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("edit", help="change an entry")
    s.add_argument("name")
    s.add_argument("--username")
    s.add_argument("--url")
    s.add_argument("--notes")
    s.add_argument("--tag", action="append")
    pw = s.add_mutually_exclusive_group()
    pw.add_argument("--password", action="store_true", help="type a new password")
    pw.add_argument("--generate", action="store_true", help="generate a new password")
    gen_opts(s)
    s.set_defaults(func=cmd_edit)

    s = sub.add_parser("rm", help="delete an entry")
    s.add_argument("name")
    s.add_argument("--yes", action="store_true")
    s.set_defaults(func=cmd_rm)

    s = sub.add_parser("generate", help="generate passwords without saving them")
    s.add_argument("--count", type=int, default=1)
    gen_opts(s)
    s.set_defaults(func=cmd_generate)

    s = sub.add_parser("audit", help="find weak, reused, old or breached passwords")
    s.add_argument("--online", action="store_true", help="also check Have I Been Pwned")
    s.add_argument("--fail", action="store_true", help="exit with code 2 if issues are found")
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("passwd", help="change the master password")
    s.add_argument("--rotate-key", action="store_true", help="also replace the data key")
    s.set_defaults(func=cmd_passwd)

    s = sub.add_parser("info", help="show encryption parameters (no password needed)")
    s.set_defaults(func=cmd_info)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.vault = args.vault or default_vault()
    prompter = Prompter(args.password_stdin)
    try:
        return args.func(args, prompter)
    except DecryptionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except (VaultError, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
