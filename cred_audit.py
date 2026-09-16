#!/usr/bin/env python3
"""cred-audit — password strength and credential policy auditing.

Scores passwords on real resistance to offline cracking rather than on the
"one uppercase, one symbol" rules that produce Password1! and call it strong.
It measures search-space entropy, penalises the structures crackers exploit
first (keyboard walks, dates, leet substitutions, repeats), checks policy
compliance, and can test a password against the Have I Been Pwned breach
corpus without ever transmitting the password.

Standard library only.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import math
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"

# Character classes and the search space each one contributes.
CHARSETS = [
    (re.compile(r"[a-z]"), 26, "lowercase"),
    (re.compile(r"[A-Z]"), 26, "uppercase"),
    (re.compile(r"[0-9]"), 10, "digits"),
    (re.compile(r"[ !-/:-@\[-`{-~]"), 33, "symbols"),
]

# Rows of a QWERTY keyboard, used to spot sequential walks like "qwerty".
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

# The passwords that appear at the top of essentially every cracking wordlist.
COMMON_BASES = {
    "password", "passwd", "welcome", "admin", "administrator", "root",
    "letmein", "monkey", "dragon", "qwerty", "abc", "iloveyou", "sunshine",
    "princess", "football", "baseball", "master", "shadow", "superman",
    "trustno", "login", "hello", "freedom", "whatever", "qazwsx", "test",
    "guest", "user", "changeme", "secret", "summer", "winter", "spring",
}

# Characters attackers substitute automatically when mangling a wordlist.
LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a",
                          "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})


@dataclass
class PolicyResult:
    passed: bool
    violations: list[str] = field(default_factory=list)


@dataclass
class Audit:
    label: str
    length: int
    charsets: list[str]
    entropy_bits: float
    effective_bits: float
    rating: str
    crack_time: str
    weaknesses: list[str] = field(default_factory=list)
    breached: int | None = None
    policy: PolicyResult | None = None


def raw_entropy(password: str) -> tuple[float, list[str]]:
    """Shannon search-space entropy: length x log2(alphabet size)."""
    pool = 0
    used = []
    for pattern, size, name in CHARSETS:
        if pattern.search(password):
            pool += size
            used.append(name)
    if pool == 0:
        return 0.0, []
    return len(password) * math.log2(pool), used


def find_weaknesses(password: str) -> tuple[list[str], float]:
    """Detect crackable structure. Returns (messages, entropy penalty in bits)."""
    messages: list[str] = []
    penalty = 0.0
    lowered = password.lower()
    normalised = lowered.translate(LEET_MAP)

    # A dictionary word at the core makes the whole thing a mangling target.
    for base in COMMON_BASES:
        if base in normalised:
            messages.append(
                f"contains the common word '{base}' — the first thing any "
                f"wordlist attack tries, including leet-substituted forms")
            penalty += 18
            break

    # Keyboard walks: three or more adjacent keys in a row.
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 2):
            run = row[i:i + 4]
            if run in lowered or run[::-1] in lowered:
                messages.append(f"contains the keyboard sequence '{run}'")
                penalty += 12
                break

    # Alphabetic or numeric runs: abcd, 1234.
    if re.search(r"(abc|bcd|cde|def|123|234|345|456|567|678|789|890)", lowered):
        messages.append("contains a sequential run (abc / 123)")
        penalty += 10

    # Repeated characters: aaa, 111.
    if re.search(r"(.)\1{2,}", password):
        messages.append("contains a character repeated three or more times")
        penalty += 8

    # A year or date suffix is the single most common mangling rule.
    if re.search(r"(19|20)\d{2}$", password):
        messages.append("ends with a year — a standard mangling rule")
        penalty += 10

    # Capital-first, digits-last is the shape most policies accidentally force.
    if re.fullmatch(r"[A-Z][a-z]+\d{1,4}[!@#$%^&*]?", password):
        messages.append(
            "follows the predictable Capitalised-word + digits + symbol shape "
            "that password policies tend to produce")
        penalty += 12

    if len(set(password)) <= max(2, len(password) // 4):
        messages.append("uses very few distinct characters")
        penalty += 8

    return messages, penalty


def crack_time_estimate(bits: float, guesses_per_second: float = 1e11) -> str:
    """Offline attack estimate against a fast hash on commodity GPUs."""
    if bits <= 0:
        return "instantly"
    seconds = (2 ** (bits - 1)) / guesses_per_second
    units = [
        ("seconds", 1), ("minutes", 60), ("hours", 3600), ("days", 86400),
        ("months", 2_592_000), ("years", 31_536_000),
        ("centuries", 3_153_600_000),
    ]
    if seconds < 1:
        return "instantly"
    label, size = units[0]
    for name, divisor in units:
        if seconds >= divisor:
            label, size = name, divisor
    value = seconds / size
    if value > 1e6:
        return f"{value:.1e} {label}"
    return f"{value:,.0f} {label}"


def rate(bits: float) -> str:
    if bits < 28:
        return "very weak"
    if bits < 36:
        return "weak"
    if bits < 60:
        return "moderate"
    if bits < 80:
        return "strong"
    return "very strong"


def check_policy(password: str, min_length: int, require_classes: int,
                 forbid_common: bool) -> PolicyResult:
    violations = []
    if len(password) < min_length:
        violations.append(f"shorter than the {min_length} character minimum")
    _, used = raw_entropy(password)
    if len(used) < require_classes:
        violations.append(
            f"uses {len(used)} character class(es), policy requires "
            f"{require_classes}")
    if forbid_common:
        normalised = password.lower().translate(LEET_MAP)
        if any(base in normalised for base in COMMON_BASES):
            violations.append("based on a common dictionary word")
    return PolicyResult(passed=not violations, violations=violations)


def check_breach_corpus(password: str, timeout: float = 8.0) -> int | None:
    """Query Have I Been Pwned using k-anonymity.

    Only the first five characters of the SHA-1 hash leave this machine. The
    service returns every suffix in that bucket and the match is made locally,
    so the password itself is never transmitted or revealed.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    request = urllib.request.Request(
        HIBP_RANGE_URL + prefix,
        headers={"User-Agent": "cred-audit/1.0", "Add-Padding": "true"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, OSError):
        return None
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate == suffix:
            return int(count)
    return 0


def audit_password(password: str, label: str, args) -> Audit:
    bits, charsets = raw_entropy(password)
    weaknesses, penalty = find_weaknesses(password)
    effective = max(0.0, bits - penalty)

    result = Audit(
        label=label,
        length=len(password),
        charsets=charsets,
        entropy_bits=round(bits, 1),
        effective_bits=round(effective, 1),
        rating=rate(effective),
        crack_time=crack_time_estimate(effective),
        weaknesses=weaknesses,
        policy=check_policy(password, args.min_length, args.classes,
                            not args.allow_common),
    )
    if args.check_breaches:
        result.breached = check_breach_corpus(password)
        if result.breached:
            result.rating = "compromised"
            result.crack_time = "instantly (already in breach corpora)"
    return result


def print_audit(audit: Audit) -> None:
    print(f"\n  {audit.label}")
    print(f"    Length        : {audit.length}")
    print(f"    Classes       : {', '.join(audit.charsets) or 'none'}")
    print(f"    Entropy       : {audit.entropy_bits} bits raw / "
          f"{audit.effective_bits} bits effective")
    print(f"    Rating        : {audit.rating.upper()}")
    print(f"    Offline crack : {audit.crack_time}")

    if audit.breached is not None:
        if audit.breached > 0:
            print(f"    Breach corpus : FOUND {audit.breached:,} times — "
                  f"must not be used")
        else:
            print(f"    Breach corpus : not found")

    if audit.weaknesses:
        print(f"    Weaknesses    :")
        for item in audit.weaknesses:
            print(f"      - {item}")

    if audit.policy and not audit.policy.passed:
        print(f"    Policy        : FAILED")
        for item in audit.policy.violations:
            print(f"      - {item}")
    elif audit.policy:
        print(f"    Policy        : passed")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Password strength and credential policy auditing.")
    parser.add_argument("-p", "--password",
                        help="password to audit (omit for a hidden prompt)")
    parser.add_argument("-f", "--file",
                        help="audit every password in this file, one per line")
    parser.add_argument("--min-length", type=int, default=12,
                        help="policy: minimum length (default 12)")
    parser.add_argument("--classes", type=int, default=3,
                        help="policy: required character classes (default 3)")
    parser.add_argument("--allow-common", action="store_true",
                        help="policy: permit dictionary-word based passwords")
    parser.add_argument("--check-breaches", action="store_true",
                        help="check Have I Been Pwned via k-anonymity "
                             "(the password itself is never transmitted)")
    parser.add_argument("-o", "--output", help="write the JSON report to this file")
    args = parser.parse_args(argv)

    audits: list[Audit] = []

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                entries = [line.rstrip("\n") for line in fh if line.strip()]
        except OSError as exc:
            print(f"Could not read {args.file}: {exc}", file=sys.stderr)
            return 2
        for index, password in enumerate(entries, start=1):
            audits.append(audit_password(password, f"entry #{index}", args))
    else:
        password = args.password or getpass.getpass("Password to audit: ")
        if not password:
            print("No password supplied.", file=sys.stderr)
            return 2
        audits.append(audit_password(password, "password", args))

    for audit in audits:
        print_audit(audit)

    if args.file:
        failed = sum(1 for a in audits if a.policy and not a.policy.passed)
        print(f"  {len(audits)} audited, {failed} failed policy.\n")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump([asdict(a) for a in audits], fh, indent=2)
        print(f"  Report written to {args.output}\n")

    return 1 if any(a.policy and not a.policy.passed for a in audits) else 0


if __name__ == "__main__":
    raise SystemExit(main())
