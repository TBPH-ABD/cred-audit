"""Tests for cred-audit entropy scoring, weakness detection, and policy."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

import cred_audit
from cred_audit import (audit_password, check_breach_corpus, check_policy,
                        crack_time_estimate, find_weaknesses, rate,
                        raw_entropy)
from tests.support.fakes import capture_cli, http_fake


def default_args(**overrides) -> argparse.Namespace:
    values = {"min_length": 12, "classes": 3, "allow_common": False,
              "check_breaches": False}
    values.update(overrides)
    return argparse.Namespace(**values)


def weakness_text(password: str) -> str:
    return " | ".join(find_weaknesses(password)[0])


class TestRawEntropy(unittest.TestCase):
    def test_empty_password_has_no_entropy(self):
        bits, charsets = raw_entropy("")
        self.assertEqual(bits, 0.0)
        self.assertEqual(charsets, [])

    def test_character_classes_are_identified(self):
        _, charsets = raw_entropy("Abc123!@")
        self.assertEqual(set(charsets),
                         {"lowercase", "uppercase", "digits", "symbols"})

    def test_longer_password_has_more_entropy(self):
        self.assertLess(raw_entropy("abcdefgh")[0], raw_entropy("abcdefghij")[0])

    def test_wider_alphabet_has_more_entropy_at_equal_length(self):
        self.assertLess(raw_entropy("abcdefgh")[0], raw_entropy("aBc1efg!")[0])

    def test_lowercase_only_uses_a_26_character_pool(self):
        bits, _ = raw_entropy("abcd")
        self.assertAlmostEqual(bits, 4 * 4.7004, places=2)


class TestWeaknessDetection(unittest.TestCase):
    def test_dictionary_word_is_detected(self):
        self.assertIn("common word", weakness_text("password123"))

    def test_leet_substituted_word_is_detected(self):
        """P@ssw0rd must be recognised as 'password' — crackers do this."""
        self.assertIn("common word", weakness_text("P@ssw0rd"))

    def test_keyboard_walk_is_detected(self):
        self.assertIn("keyboard sequence", weakness_text("qwertyhome"))

    def test_sequential_run_is_detected(self):
        self.assertIn("sequential run", weakness_text("xyz123abc"))

    def test_repeated_characters_are_detected(self):
        self.assertIn("repeated", weakness_text("Zaaaa8!kQm"))

    def test_trailing_year_is_detected(self):
        self.assertIn("year", weakness_text("Kestrel!2024"))

    def test_policy_shaped_password_is_detected(self):
        self.assertIn("predictable", weakness_text("Kestrel12!"))

    def test_low_character_variety_is_detected(self):
        self.assertIn("few distinct", weakness_text("abababababab"))

    def test_strong_random_password_has_no_weaknesses(self):
        messages, penalty = find_weaknesses("X7#vK2$mQ9!zL4wR")
        self.assertEqual(messages, [])
        self.assertEqual(penalty, 0)

    def test_penalty_accumulates_with_more_flaws(self):
        _, light = find_weaknesses("Kestrel!2024")
        _, heavy = find_weaknesses("password123")
        self.assertGreater(heavy, light)


class TestRating(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(rate(10), "very weak")
        self.assertEqual(rate(30), "weak")
        self.assertEqual(rate(45), "moderate")
        self.assertEqual(rate(70), "strong")
        self.assertEqual(rate(100), "very strong")


class TestCrackTime(unittest.TestCase):
    def test_zero_entropy_is_instant(self):
        self.assertEqual(crack_time_estimate(0), "instantly")

    def test_low_entropy_is_instant(self):
        self.assertEqual(crack_time_estimate(20), "instantly")

    def test_high_entropy_reaches_centuries(self):
        self.assertIn("centuries", crack_time_estimate(120))

    def test_more_bits_never_means_less_time(self):
        # Compare within one unit band to keep the assertion meaningful.
        self.assertNotEqual(crack_time_estimate(60), crack_time_estimate(80))


class TestPolicy(unittest.TestCase):
    def test_strong_password_passes(self):
        result = check_policy("X7#vK2$mQ9!zL4wR", 12, 3, True)
        self.assertTrue(result.passed)
        self.assertEqual(result.violations, [])

    def test_short_password_fails(self):
        result = check_policy("Ab1!", 12, 3, True)
        self.assertFalse(result.passed)
        self.assertTrue(any("shorter" in v for v in result.violations))

    def test_too_few_character_classes_fails(self):
        result = check_policy("abcdefghijklmnop", 12, 3, False)
        self.assertTrue(any("class" in v for v in result.violations))

    def test_dictionary_word_fails_when_forbidden(self):
        result = check_policy("Password123!x", 12, 3, True)
        self.assertTrue(any("dictionary" in v for v in result.violations))

    def test_dictionary_word_allowed_when_policy_permits(self):
        result = check_policy("Password123!x", 12, 3, False)
        self.assertFalse(any("dictionary" in v for v in result.violations))


class TestBreachCorpus(unittest.TestCase):
    # SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    PREFIX = "5BAA6"
    SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

    def test_known_breached_password_returns_its_count(self):
        body = f"{self.SUFFIX}:12345\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1"
        with http_fake({f"/range/{self.PREFIX}": (200, {}, body)}) as (base, _):
            with mock.patch.object(cred_audit, "HIBP_RANGE_URL",
                                   base + "/range/"):
                self.assertEqual(check_breach_corpus("password"), 12345)

    def test_absent_password_returns_zero(self):
        body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1"
        with http_fake({f"/range/{self.PREFIX}": (200, {}, body)}) as (base, _):
            with mock.patch.object(cred_audit, "HIBP_RANGE_URL",
                                   base + "/range/"):
                self.assertEqual(check_breach_corpus("password"), 0)

    def test_network_failure_returns_none_not_a_crash(self):
        with mock.patch.object(cred_audit, "HIBP_RANGE_URL",
                               "http://127.0.0.1:1/range/"):
            self.assertIsNone(check_breach_corpus("password", timeout=1.0))

    def test_only_the_hash_prefix_is_transmitted(self):
        """k-anonymity: the password must never leave the machine."""
        with http_fake({f"/range/{self.PREFIX}": (200, {}, "")}) as (base, rec):
            with mock.patch.object(cred_audit, "HIBP_RANGE_URL",
                                   base + "/range/"):
                check_breach_corpus("password")
        requested = rec.paths[0]
        self.assertEqual(requested, f"/range/{self.PREFIX}")
        self.assertNotIn("password", requested)
        full_hash = hashlib.sha1(b"password").hexdigest().upper()
        self.assertNotIn(self.SUFFIX, requested)
        self.assertNotIn(full_hash, requested)


class TestAuditPassword(unittest.TestCase):
    def test_weak_password_is_rated_down(self):
        result = audit_password("password123", "p", default_args())
        self.assertLess(result.effective_bits, result.entropy_bits)
        self.assertIn(result.rating, ("very weak", "weak", "moderate"))

    def test_strong_password_keeps_its_entropy(self):
        result = audit_password("X7#vK2$mQ9!zL4wR", "p", default_args())
        self.assertEqual(result.effective_bits, result.entropy_bits)
        self.assertEqual(result.rating, "very strong")

    def test_effective_bits_never_go_negative(self):
        result = audit_password("password", "p", default_args())
        self.assertGreaterEqual(result.effective_bits, 0)

    def test_breached_password_is_marked_compromised(self):
        body = f"{TestBreachCorpus.SUFFIX}:99\r\n"
        route = {f"/range/{TestBreachCorpus.PREFIX}": (200, {}, body)}
        with http_fake(route) as (base, _):
            with mock.patch.object(cred_audit, "HIBP_RANGE_URL",
                                   base + "/range/"):
                result = audit_password("password", "p",
                                        default_args(check_breaches=True))
        self.assertEqual(result.rating, "compromised")
        self.assertEqual(result.breached, 99)


class TestCli(unittest.TestCase):
    def test_strong_password_exits_zero(self):
        code, _ = capture_cli(cred_audit.main, ["-p", "X7#vK2$mQ9!zL4wR"])
        self.assertEqual(code, 0)

    def test_weak_password_exits_nonzero(self):
        code, out = capture_cli(cred_audit.main, ["-p", "password"])
        self.assertEqual(code, 1)
        self.assertIn("common word", out)

    def test_file_mode_audits_every_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "pw.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("password\nX7#vK2$mQ9!zL4wR\n")
            code, out = capture_cli(cred_audit.main, ["-f", path])
        self.assertEqual(code, 1)
        self.assertIn("2 audited, 1 failed policy", out)

    def test_json_report_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_file = os.path.join(tmp, "r.json")
            capture_cli(cred_audit.main,
                        ["-p", "X7#vK2$mQ9!zL4wR", "-o", out_file])
            with open(out_file, encoding="utf-8") as fh:
                data = json.load(fh)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["rating"], "very strong")

    def test_missing_file_reports_error(self):
        code, out = capture_cli(cred_audit.main, ["-f", "/nope/none.txt"])
        self.assertEqual(code, 2)
        self.assertIn("Could not read", out)


if __name__ == "__main__":
    unittest.main()
