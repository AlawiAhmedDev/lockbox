"""Password health checks: weak, common, reused, old, and (optionally) breached.

The breach check uses the Have I Been Pwned "range" API with k-anonymity:
only the first 5 hex characters of the password's SHA-1 leave the machine,
and the comparison with the returned suffixes happens locally. The API never
learns the password or even its full hash.
"""

from __future__ import annotations

import hashlib
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from .generator import estimate_entropy
from .vault import Entry

HIBP_URL = "https://api.pwnedpasswords.com/range/{prefix}"
MIN_LENGTH = 12
MIN_ENTROPY = 60
MAX_AGE_DAYS = 365

# A few of the most common passwords in public breach statistics.
COMMON = {
    "123456", "123456789", "12345678", "12345", "1234567", "1234567890", "111111", "000000",
    "password", "password1", "password123", "qwerty", "qwerty123", "azerty", "azerty123",
    "abc123", "iloveyou", "admin", "admin123", "welcome", "letmein", "monkey", "dragon",
    "football", "sunshine", "princess", "master", "login", "passw0rd", "p@ssw0rd",
    "123123", "654321", "superman", "trustno1", "motdepasse", "bonjour", "soleil", "maroc",
}


@dataclass
class Finding:
    entry: str
    issues: list[str] = field(default_factory=list)


def _age_days(entry: Entry, now: datetime) -> int:
    try:
        updated = datetime.fromisoformat(entry.updated)
    except ValueError:
        return 0
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)
    return (now - updated).days


def pwned_count(password: str, fetch: Callable[[str], str] | None = None) -> int:
    """How many times the password appears in known breaches (0 = not found)."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324 - HIBP protocol
    prefix, suffix = digest[:5], digest[5:]
    body = (fetch or _fetch_range)(prefix)
    for line in body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate == suffix:
            return int(count or 0)
    return 0


def _fetch_range(prefix: str) -> str:
    req = urllib.request.Request(HIBP_URL.format(prefix=prefix),
                                 headers={"Add-Padding": "true", "User-Agent": "lockbox"})
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - fixed https URL
        return resp.read().decode("utf-8")


def audit(entries: list[Entry], check_breaches: bool = False,
          fetch: Callable[[str], str] | None = None, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    by_password = defaultdict(list)
    for e in entries:
        by_password[e.password].append(e.name)

    findings = []
    for e in entries:
        f = Finding(e.name)
        pw = e.password
        if pw.lower() in COMMON:
            f.issues.append("very common password")
        if len(pw) < MIN_LENGTH:
            f.issues.append(f"short ({len(pw)} characters, aim for {MIN_LENGTH}+)")
        elif estimate_entropy(pw) < MIN_ENTROPY:
            f.issues.append(f"low entropy (~{estimate_entropy(pw):.0f} bits)")
        for part in (e.username, e.name):
            if part and len(part) >= 3 and part.lower() in pw.lower():
                f.issues.append(f"contains '{part}'")
                break
        others = [n for n in by_password[pw] if n != e.name]
        if others:
            f.issues.append("reused in " + ", ".join(sorted(others)))
        age = _age_days(e, now)
        if age > MAX_AGE_DAYS:
            f.issues.append(f"not changed for {age} days")
        if check_breaches:
            n = pwned_count(pw, fetch)
            if n:
                f.issues.append(f"found {n:,} times in data breaches")
        if f.issues:
            findings.append(f)
    return findings
