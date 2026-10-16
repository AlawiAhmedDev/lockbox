"""Password generation with a cryptographically secure RNG (``secrets``)."""

from __future__ import annotations

import math
import secrets
import string

AMBIGUOUS = set("Il1O0o|`'\"")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/~"


def generate(length: int = 20, lower: bool = True, upper: bool = True, digits: bool = True,
             symbols: bool = True, exclude_ambiguous: bool = False) -> str:
    """Random password containing at least one character of each selected class."""
    classes = [c for c, on in ((string.ascii_lowercase, lower), (string.ascii_uppercase, upper),
                               (string.digits, digits), (SYMBOLS, symbols)) if on]
    if exclude_ambiguous:
        classes = ["".join(ch for ch in c if ch not in AMBIGUOUS) for c in classes]
    classes = [c for c in classes if c]
    if not classes:
        raise ValueError("select at least one character class")
    if length < len(classes):
        raise ValueError(f"length must be at least {len(classes)}")
    alphabet = "".join(classes)
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        # Rejection sampling keeps the distribution uniform over valid passwords
        if all(any(ch in c for ch in pw) for c in classes):
            return pw


def entropy_bits(length: int, alphabet_size: int) -> float:
    """Entropy of a password drawn uniformly at random (the generator's output)."""
    return length * math.log2(alphabet_size) if alphabet_size > 1 else 0.0


def estimate_entropy(password: str) -> float:
    """Upper-bound estimate for a password of unknown origin: assumes each
    character was drawn from the classes it uses. Human-chosen passwords are
    weaker than this, which is why the audit also checks a list of common ones."""
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(not c.isalnum() for c in password):
        size += len(SYMBOLS)
    return entropy_bits(len(password), size)
