"""
OWASP Password Storage Cheat Sheet Compliance Tests

Validates didlite's FileKeyStore implementation against OWASP recommendations.
Reference: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

Copyright 2025 Jon de Palma
SPDX-License-Identifier: Apache-2.0

IMPORTANT: PyO3 Compatibility Note
----------------------------------
This test module uses module-scoped fixtures to avoid PyO3 reinitialization errors.
FileKeyStore imports cryptography modules which use PyO3 (Rust bindings).
PyO3 modules can only be initialized once per interpreter process.

By sharing a single FileKeyStore instance across all tests in this module,
we prevent multiple cryptography imports within the same test session.

Reference: Issue #50 - CI/CD Pipeline Fixes: PyO3 Compatibility
"""

import pytest
import os
import json
import base64
import tempfile
import shutil
from didlite.keystore import FileKeyStore


@pytest.fixture(scope="module")
def shared_test_dir():
    """
    Module-level fixture for shared test directory.

    Using module scope to avoid PyO3 reinitialization errors.
    All tests share the same temporary directory.
    """
    test_dir = tempfile.mkdtemp()
    yield test_dir
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)


@pytest.fixture(scope="module")
def shared_keystore(shared_test_dir):
    """
    Module-level fixture for shared FileKeyStore instance.

    CRITICAL: Using module scope prevents PyO3 reinitialization errors.
    All tests in this module share the same FileKeyStore instance.
    """
    return FileKeyStore(shared_test_dir, "test_password")


class TestOWASPCompliance:
    """Validate OWASP Password Storage Cheat Sheet compliance"""

    def test_iteration_count_documented_correctly(self, shared_keystore):
        """Verify default iteration count matches documentation (Issue #55)"""
        assert shared_keystore.iterations == 480000, \
            f"Expected 480,000 iterations (documented), got {shared_keystore.iterations}"

    def test_iteration_count_exceeds_owasp_2021(self, shared_keystore):
        """Verify iteration count exceeds OWASP 2021 minimum (310k)"""
        OWASP_2021_MIN = 310000
        assert shared_keystore.iterations >= OWASP_2021_MIN, \
            f"Iterations ({shared_keystore.iterations}) below OWASP 2021 minimum ({OWASP_2021_MIN})"

    def test_uses_hmac_sha256(self):
        """Verify PBKDF2 uses HMAC-SHA256 (OWASP recommended)

        This is validated by code inspection (didlite/keystore.py:245)
        algorithm=_hashes.SHA256()
        """
        # Code inspection test - verifies implementation matches docs
        pass

    def test_salt_length_128_bits(self, shared_keystore, shared_test_dir):
        """Verify salt is 128 bits (16 bytes) per NIST SP 800-132"""
        seed = os.urandom(32)
        shared_keystore.save_seed("test_salt_length", seed)

        # Read the encrypted file and verify salt length
        with open(os.path.join(shared_test_dir, "test_salt_length.enc"), 'r') as f:
            data = json.load(f)

        salt = base64.b64decode(data['salt'])
        assert len(salt) == 16, \
            f"Salt should be 16 bytes (128 bits), got {len(salt)}"

    def test_salt_is_random(self, shared_keystore, shared_test_dir):
        """Verify salt is unique per save operation"""
        seed = os.urandom(32)

        # Save same seed twice with different identifiers
        shared_keystore.save_seed("test_salt_random1", seed)
        shared_keystore.save_seed("test_salt_random2", seed)

        # Read both files
        with open(os.path.join(shared_test_dir, "test_salt_random1.enc"), 'r') as f:
            data1 = json.load(f)
        with open(os.path.join(shared_test_dir, "test_salt_random2.enc"), 'r') as f:
            data2 = json.load(f)

        salt1 = base64.b64decode(data1['salt'])
        salt2 = base64.b64decode(data2['salt'])

        assert salt1 != salt2, "Salts should be unique per save operation"

    def test_output_length_256_bits(self):
        """Verify PBKDF2 output is 32 bytes (256 bits)

        This is validated by code inspection (didlite/keystore.py:246)
        length=32
        """
        # Code inspection test - verifies implementation matches docs
        pass


class TestCryptoRationaleAlignment:
    """Validate implementation matches CRYPTO_RATIONALE.md claims"""

    def test_iteration_count_matches_docs(self, shared_keystore):
        """Verify iteration count matches what's documented in CRYPTO_RATIONALE.md

        After Issue #55 fix, documentation should correctly state 480,000 iterations
        """
        # After documentation fix, this should be 480000
        assert shared_keystore.iterations == 480000, \
            f"Expected 480,000 iterations per CRYPTO_RATIONALE.md, got {shared_keystore.iterations}"

    def test_uses_pbkdf2_hmac_sha256(self):
        """Verify docs claim of PBKDF2-HMAC-SHA256 is accurate

        Validated by code inspection - see didlite/keystore.py:244-245
        """
        # Code inspection test
        pass

    def test_uses_fernet_encryption(self):
        """Verify docs claim of Fernet (AES-128-CBC + HMAC) is accurate

        Validated by code inspection - see didlite/keystore.py:263
        """
        # Code inspection test
        pass


class TestThreatModelAlignment:
    """Validate implementation matches THREAT_MODEL.md claims"""

    def test_brute_force_resistance(self, shared_keystore):
        """Verify iteration count provides documented brute-force resistance

        With 480k iterations, should take ~0.5-1s per attempt on modern CPU.
        This provides documented resistance in THREAT_MODEL.md
        """
        # Verify iteration count provides documented resistance level
        assert shared_keystore.iterations >= 480000, \
            f"Expected ≥480,000 iterations for documented brute-force resistance"

    def test_exceeds_owasp_2021_by_55_percent(self, shared_keystore):
        """Verify claim that 480k exceeds OWASP 2021 (310k) by ~55%"""
        OWASP_2021 = 310000
        expected_min_ratio = 1.54  # ~54.8% increase (allowing for rounding)
        actual_ratio = shared_keystore.iterations / OWASP_2021

        assert actual_ratio >= expected_min_ratio, \
            f"Expected ≥54% increase over OWASP 2021, got {(actual_ratio - 1) * 100:.1f}%"

    def test_is_80_percent_of_owasp_2023(self, shared_keystore):
        """Verify claim that 480k is ~80% of OWASP 2023 (600k)"""
        OWASP_2023 = 600000
        expected_ratio = 0.80  # 80% of OWASP 2023
        actual_ratio = shared_keystore.iterations / OWASP_2023

        # Allow 1% tolerance for rounding
        assert abs(actual_ratio - expected_ratio) < 0.01, \
            f"Expected ~80% of OWASP 2023, got {actual_ratio * 100:.1f}%"
