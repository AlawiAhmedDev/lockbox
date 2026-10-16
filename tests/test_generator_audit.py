import hashlib
import string
from datetime import datetime, timedelta, timezone

import pytest

from lockbox.audit import audit, pwned_count
from lockbox.generator import AMBIGUOUS, SYMBOLS, estimate_entropy, generate
from lockbox.vault import Entry


def test_generate_length_and_classes():
    for _ in range(200):
        pw = generate(16)
        assert len(pw) == 16
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)


def test_generate_options():
    assert all(c.isalnum() for c in generate(30, symbols=False))
    assert not set(generate(200, exclude_ambiguous=True)) & AMBIGUOUS
    assert len({generate(20) for _ in range(100)}) == 100
    with pytest.raises(ValueError):
        generate(3)
    with pytest.raises(ValueError):
        generate(10, lower=False, upper=False, digits=False, symbols=False)


def test_entropy_estimate():
    assert estimate_entropy("abc") < estimate_entropy("aB3!")
    assert estimate_entropy(generate(20)) > 120


def _e(name, pw, username="", days_old=0):
    when = (datetime.now(timezone.utc) - timedelta(days=days_old)).isoformat()
    return Entry(name=name, password=pw, username=username, updated=when)


def test_audit_findings():
    entries = [
        _e("bank", "azerty123"), _e("forum", "azerty123"),
        _e("shop", "alawi-shop-2020!", username="alawi"),
        _e("old", generate(20), days_old=400),
        _e("good", generate(20)),
    ]
    found = {f.entry: f.issues for f in audit(entries)}
    assert "very common password" in found["bank"]
    assert any("reused in forum" in i for i in found["bank"])
    assert any("contains 'alawi'" in i for i in found["shop"])
    assert any("not changed for 400 days" in i for i in found["old"])
    assert "good" not in found


def test_pwned_check_uses_k_anonymity():
    password = "P@ssw0rd"
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    sent = []

    def fake_fetch(prefix):
        sent.append(prefix)
        return f"0000000000000000000000000000000000A:3\r\n{digest[5:]}:42\r\n"

    assert pwned_count(password, fake_fetch) == 42
    assert sent == [digest[:5]]          # only 5 hex chars left the machine
    assert pwned_count("not in the fake list", lambda p: "ABC:1") == 0


def test_audit_reports_breaches():
    pw = "Tr0ub4dor&3-but-longer"
    suffix = hashlib.sha1(pw.encode()).hexdigest().upper()[5:]
    found = audit([_e("x", pw)], check_breaches=True, fetch=lambda p: f"{suffix}:7")
    assert any("found 7 times" in i for i in found[0].issues)
