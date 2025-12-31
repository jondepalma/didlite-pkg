# Copyright 2025 Jon DePalma
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Security-focused test suite for didlite

Tests malformed inputs, attack scenarios, and cryptographic properties
to verify security fixes from Phase 1.1 security audit.

References:
- SECURITY_FINDINGS.md (Phase 1.1 Cryptographic Implementation Review)
- Issues #4, #5, #6, #7 (GitHub security findings)
"""

import pytest
import multibase
from didlite.core import AgentIdentity, resolve_did_to_key, ED25519_CODEC
from didlite.jws import create_jws, verify_jws
from nacl.exceptions import BadSignatureError


class TestSeedValidation:
    """
    Test seed validation at PyNaCl boundary (Issue #4, CRIT-1)

    Verifies that AgentIdentity rejects malformed seeds before
    passing to C code.
    """

    def test_seed_must_be_bytes(self):
        """Reject non-bytes seed types"""
        with pytest.raises(TypeError, match="seed must be bytes"):
            AgentIdentity(seed="not bytes")

        with pytest.raises(TypeError, match="seed must be bytes"):
            AgentIdentity(seed=12345)

        with pytest.raises(TypeError, match="seed must be bytes"):
            AgentIdentity(seed=['list', 'of', 'things'])

    def test_seed_must_be_32_bytes(self):
        """Reject seeds that are not exactly 32 bytes"""
        # Too short
        with pytest.raises(ValueError, match="seed must be exactly 32 bytes, got 0"):
            AgentIdentity(seed=b"")

        with pytest.raises(ValueError, match="seed must be exactly 32 bytes, got 1"):
            AgentIdentity(seed=b"x")

        with pytest.raises(ValueError, match="seed must be exactly 32 bytes, got 5"):
            AgentIdentity(seed=b"short")

        with pytest.raises(ValueError, match="seed must be exactly 32 bytes, got 31"):
            AgentIdentity(seed=b"x" * 31)

        # Too long
        with pytest.raises(ValueError, match="seed must be exactly 32 bytes, got 33"):
            AgentIdentity(seed=b"x" * 33)

        with pytest.raises(ValueError, match="seed must be exactly 32 bytes, got 100"):
            AgentIdentity(seed=b"x" * 100)

        with pytest.raises(ValueError, match="seed must be exactly 32 bytes, got 1000"):
            AgentIdentity(seed=b"x" * 1000)

    def test_valid_32_byte_seed_accepted(self):
        """Accept valid 32-byte seeds"""
        valid_seed = b"x" * 32
        identity = AgentIdentity(seed=valid_seed)
        assert identity.did.startswith("did:key:")

    def test_none_seed_generates_random_identity(self):
        """None seed should generate random identity"""
        identity = AgentIdentity(seed=None)
        assert identity.did.startswith("did:key:")

    def test_no_seed_generates_random_identity(self):
        """No seed argument should generate random identity"""
        identity = AgentIdentity()
        assert identity.did.startswith("did:key:")


class TestDIDResolutionValidation:
    """
    Test DID resolution validation (Issue #5, CRIT-2/3/4)

    Verifies that resolve_did_to_key() validates:
    - Minimum decoded length (CRIT-3)
    - Multicodec prefix (CRIT-4)
    - Public key size (CRIT-2)
    """

    def test_did_minimum_length_validation(self):
        """Reject DIDs that decode to < 34 bytes (Issue #5, CRIT-3)"""
        # Create minimal multibase-encoded strings
        # These will decode to fewer than 34 bytes

        # 1 byte decoded (too short)
        short_multibase = multibase.encode('base58btc', b'x')
        short_did = f"did:key:{short_multibase.decode('utf-8')}"
        with pytest.raises(ValueError, match="decoded key must be at least 34 bytes"):
            resolve_did_to_key(short_did)

        # 10 bytes decoded (still too short)
        short_multibase = multibase.encode('base58btc', b'x' * 10)
        short_did = f"did:key:{short_multibase.decode('utf-8')}"
        with pytest.raises(ValueError, match="decoded key must be at least 34 bytes"):
            resolve_did_to_key(short_did)

        # 33 bytes decoded (one short of minimum)
        short_multibase = multibase.encode('base58btc', b'x' * 33)
        short_did = f"did:key:{short_multibase.decode('utf-8')}"
        with pytest.raises(ValueError, match="decoded key must be at least 34 bytes"):
            resolve_did_to_key(short_did)

    def test_multicodec_prefix_validation(self):
        """Reject DIDs with wrong multicodec prefix (Issue #5, CRIT-4)"""
        # RSA multicodec: 0x1205
        rsa_codec = b'\x12\x05'
        fake_key = rsa_codec + (b'x' * 32)
        rsa_multibase = multibase.encode('base58btc', fake_key)
        rsa_did = f"did:key:{rsa_multibase.decode('utf-8')}"

        with pytest.raises(ValueError, match="expected Ed25519 multicodec prefix 0xed01"):
            resolve_did_to_key(rsa_did)

        # secp256k1 multicodec: 0xe701
        secp_codec = b'\xe7\x01'
        fake_key = secp_codec + (b'x' * 32)
        secp_multibase = multibase.encode('base58btc', fake_key)
        secp_did = f"did:key:{secp_multibase.decode('utf-8')}"

        with pytest.raises(ValueError, match="expected Ed25519 multicodec prefix 0xed01"):
            resolve_did_to_key(secp_did)

    def test_public_key_size_validation(self):
        """Reject DIDs with wrong public key size (Issue #5, CRIT-2)"""
        # Valid prefix but wrong key size (35 bytes total: 2 prefix + 33 key)
        wrong_size = ED25519_CODEC + (b'x' * 33)
        wrong_multibase = multibase.encode('base58btc', wrong_size)
        wrong_did = f"did:key:{wrong_multibase.decode('utf-8')}"

        with pytest.raises(ValueError, match="Ed25519 public key must be 32 bytes, got 33"):
            resolve_did_to_key(wrong_did)

        # Valid prefix but key too short (33 bytes total: 2 prefix + 31 key)
        # This will be caught by minimum length check instead (33 < 34)
        wrong_size = ED25519_CODEC + (b'x' * 31)
        wrong_multibase = multibase.encode('base58btc', wrong_size)
        wrong_did = f"did:key:{wrong_multibase.decode('utf-8')}"

        with pytest.raises(ValueError, match="decoded key must be at least 34 bytes"):
            resolve_did_to_key(wrong_did)

    def test_algorithm_confusion_attack(self):
        """Test that algorithm confusion attacks are prevented (Issue #5, CRIT-4)"""
        # Attacker tries to use a secp256k1 key as Ed25519
        secp_codec = b'\xe7\x01'
        secp_pubkey = b'x' * 32  # 32-byte secp256k1 public key
        malicious_did_bytes = secp_codec + secp_pubkey
        malicious_multibase = multibase.encode('base58btc', malicious_did_bytes)
        malicious_did = f"did:key:{malicious_multibase.decode('utf-8')}"

        # Should reject due to wrong multicodec prefix
        with pytest.raises(ValueError, match="expected Ed25519 multicodec prefix"):
            resolve_did_to_key(malicious_did)

    def test_valid_did_still_works(self):
        """Ensure valid DIDs still resolve correctly"""
        # Create a valid identity and resolve its DID
        identity = AgentIdentity()
        verify_key = resolve_did_to_key(identity.did)

        # Should successfully verify a signature
        message = b"test message"
        signature = identity.sign(message)
        verify_key.verify(message, signature)  # Should not raise


class TestJWSSegmentValidation:
    """
    Test JWS token segment validation (Issue #6, HIGH-1)

    Verifies that verify_jws() validates exactly 3 segments
    before attempting to unpack.
    """

    def test_empty_token(self):
        """Reject empty token string"""
        with pytest.raises(ValueError, match="expected 3 segments.*got 1"):
            verify_jws("")

    def test_single_segment_token(self):
        """Reject token with only 1 segment"""
        with pytest.raises(ValueError, match="expected 3 segments.*got 1"):
            verify_jws("onlyone")

    def test_two_segment_token(self):
        """Reject token with only 2 segments"""
        with pytest.raises(ValueError, match="expected 3 segments.*got 2"):
            verify_jws("header.payload")

    def test_four_segment_token(self):
        """Reject token with 4 segments"""
        with pytest.raises(ValueError, match="expected 3 segments.*got 4"):
            verify_jws("a.b.c.d")

    def test_many_segment_token(self):
        """Reject token with many segments"""
        with pytest.raises(ValueError, match="expected 3 segments.*got 7"):
            verify_jws("a.b.c.d.e.f.g")

    def test_valid_token_still_works(self):
        """Ensure valid tokens still verify"""
        identity = AgentIdentity()
        token = create_jws(identity, {"test": "data"})
        _, payload = verify_jws(token)
        assert payload["test"] == "data"


class TestBase64PaddingCorrectness:
    """
    Test base64 padding calculation (Issue #7, HIGH-2)

    Verifies that base64url decoding uses correct padding
    calculation instead of hardcoded "==".
    """

    def test_padding_for_various_lengths(self):
        """Test that various base64 segment lengths decode correctly"""
        identity = AgentIdentity()

        # Create tokens with various payload sizes to test different padding scenarios
        payloads = [
            {"a": "b"},  # Short payload
            {"test": "data"},  # Medium payload
            {"longer": "payload with more data"},  # Longer payload
            {"x": "y" * 100},  # Very long payload
        ]

        for payload in payloads:
            token = create_jws(identity, payload)
            _, verified_payload = verify_jws(token)
            assert verified_payload["a" if "a" in payload else ("test" if "test" in payload else ("longer" if "longer" in payload else "x"))] == payload["a" if "a" in payload else ("test" if "test" in payload else ("longer" if "longer" in payload else "x"))]

    def test_interoperability_maintained(self):
        """Ensure tokens still work with different payload sizes"""
        identity = AgentIdentity()

        # Test a range of payload sizes
        for i in range(1, 50):
            payload = {"data": "x" * i}
            token = create_jws(identity, payload)
            _, verified = verify_jws(token)
            assert verified["data"] == "x" * i


class TestMalformedInputHandling:
    """
    General malformed input tests (Phase 3.1 from SECURITY_AUDIT.md)

    Tests that the library handles all types of malformed input gracefully.
    """

    def test_invalid_did_formats(self):
        """Test various invalid DID formats"""
        invalid_dids = [
            "not-a-did",
            "did:web:example.com",  # Wrong method
            "did:key",  # Missing identifier
            "did:key:",  # Empty identifier
            "did:key:!!!",  # Invalid base58
        ]

        for did in invalid_dids:
            with pytest.raises((ValueError, Exception)):
                resolve_did_to_key(did)

    def test_oversized_inputs(self):
        """Test handling of oversized inputs"""
        # Oversized seed (1MB)
        huge_seed = b"x" * (1024 * 1024)
        with pytest.raises(ValueError, match="seed must be exactly 32 bytes"):
            AgentIdentity(seed=huge_seed)

        # Oversized DID (create a very long but structurally valid DID)
        # SECURITY: After PHASE_5 VULN-1 fix, length is checked first
        # Reference: Issue #33
        huge_data = ED25519_CODEC + (b'x' * 1000)
        huge_multibase = multibase.encode('base58btc', huge_data)
        huge_did = f"did:key:{huge_multibase.decode('utf-8')}"
        # Expect length limit error (caught before multibase decode)
        with pytest.raises(ValueError, match="Invalid DID: length exceeds 128 characters"):
            resolve_did_to_key(huge_did)


class TestCryptographicProperties:
    """
    Cryptographic property tests (Phase 3.3 from SECURITY_AUDIT.md)

    Verifies fundamental cryptographic properties hold after security fixes.
    """

    def test_signature_non_malleability(self):
        """Verify signatures cannot be modified"""
        identity = AgentIdentity()
        token = create_jws(identity, {"test": "data"})

        # Modify the signature part (replace middle of signature)
        parts = token.split('.')
        sig_part = parts[2]
        if len(sig_part) > 10:
            # Modify a character in the middle of the signature
            mid = len(sig_part) // 2
            modified_sig = sig_part[:mid] + ('X' if sig_part[mid] != 'X' else 'Y') + sig_part[mid+1:]
        else:
            # For short signatures, just append a character
            modified_sig = sig_part + 'X'
        tampered_token = f"{parts[0]}.{parts[1]}.{modified_sig}"

        # Should fail verification with tampered signature
        with pytest.raises(BadSignatureError):
            verify_jws(tampered_token)

    def test_key_independence(self):
        """Different seeds produce different DIDs"""
        seed1 = b"a" * 32
        seed2 = b"b" * 32

        identity1 = AgentIdentity(seed=seed1)
        identity2 = AgentIdentity(seed=seed2)

        assert identity1.did != identity2.did

    def test_determinism(self):
        """Same seed always produces same DID"""
        seed = b"x" * 32

        identity1 = AgentIdentity(seed=seed)
        identity2 = AgentIdentity(seed=seed)

        assert identity1.did == identity2.did

        # Signatures should also be deterministic for same message
        message = b"test"
        sig1 = identity1.sign(message)
        sig2 = identity2.sign(message)
        assert sig1 == sig2


class TestSecurityRegressions:
    """
    Regression tests to ensure security fixes don't break in future changes
    """

    def test_crit1_seed_validation_regression(self):
        """Ensure CRIT-1 fix (seed validation) doesn't regress"""
        with pytest.raises(TypeError):
            AgentIdentity(seed="string")
        with pytest.raises(ValueError):
            AgentIdentity(seed=b"short")

    def test_crit234_did_validation_regression(self):
        """Ensure CRIT-2/3/4 fixes (DID validation) don't regress"""
        # Wrong prefix (RSA multicodec 0x1205)
        wrong_prefix = b'\x12\x05' + (b'x' * 32)
        wrong_mb = multibase.encode('base58btc', wrong_prefix)
        with pytest.raises(ValueError, match="expected Ed25519 multicodec prefix"):
            resolve_did_to_key(f"did:key:{wrong_mb.decode('utf-8')}")

        # Wrong size (caught by minimum length check since 33 < 34)
        wrong_size = ED25519_CODEC + (b'x' * 31)
        wrong_mb = multibase.encode('base58btc', wrong_size)
        with pytest.raises(ValueError, match="decoded key must be at least 34 bytes"):
            resolve_did_to_key(f"did:key:{wrong_mb.decode('utf-8')}")

    def test_high1_segment_validation_regression(self):
        """Ensure HIGH-1 fix (segment validation) doesn't regress"""
        with pytest.raises(ValueError, match="expected 3 segments"):
            verify_jws("a.b")
        with pytest.raises(ValueError, match="expected 3 segments"):
            verify_jws("a.b.c.d")

    def test_high2_padding_correctness_regression(self):
        """Ensure HIGH-2 fix (padding calculation) doesn't regress"""
        # This tests that base64 decoding works correctly for various lengths
        identity = AgentIdentity()
        for length in [1, 5, 10, 20, 50, 100]:
            payload = {"data": "x" * length}
            token = create_jws(identity, payload)
            _, verified = verify_jws(token)
            assert verified["data"] == "x" * length


class TestErrorSanitization:
    """
    Tests for error message sanitization (Issues #11, #14, #15, #16)

    Ensures that error messages don't leak library internals, file paths,
    or environment variable names.
    """

    def test_jws_verification_error_messages(self):
        """Ensure verification errors don't leak library internals (Issue #11)"""
        import base64
        identity = AgentIdentity()
        token = create_jws(identity, {"test": "data"})

        # Tamper with signature to trigger BadSignatureError
        # Use a valid 64-byte signature (all zeros) that won't match
        parts = token.split('.')
        fake_signature = base64.urlsafe_b64encode(b'\x00' * 64).rstrip(b'=').decode()
        bad_token = f"{parts[0]}.{parts[1]}.{fake_signature}"

        with pytest.raises(BadSignatureError) as exc_info:
            verify_jws(bad_token)

        error_msg = str(exc_info.value)
        # Should not contain library internals
        assert "crypto_sign" not in error_msg.lower()
        assert "/usr/lib" not in error_msg
        assert ".so" not in error_msg
        assert "site-packages" not in error_msg

    def test_env_keystore_error_sanitization(self):
        """Ensure env errors don't leak variable names (Issue #16)"""
        import os
        from didlite.keystore import EnvKeyStore

        # Set invalid base64 in env var
        os.environ["TEST_SEED_AGENT1"] = "invalid-base64!@#"
        store = EnvKeyStore(prefix="TEST_SEED_")

        try:
            with pytest.raises(ValueError) as exc_info:
                store.load_seed("agent1")

            error_msg = str(exc_info.value)
            # Should not contain env var name
            assert "TEST_SEED_AGENT1" not in error_msg
            assert "DIDLITE" not in error_msg
            # Should have generic message
            assert "Failed to decode seed from environment" in error_msg
        finally:
            # Cleanup
            del os.environ["TEST_SEED_AGENT1"]

    def test_file_keystore_error_sanitization(self):
        """Ensure file errors don't leak paths (Issue #15)"""
        import tempfile
        import json
        from didlite.keystore import FileKeyStore

        with tempfile.TemporaryDirectory() as temp_dir:
            store = FileKeyStore(temp_dir, password="test")

            # Create a corrupted file to trigger decryption error
            corrupted_file = f"{temp_dir}/corrupted.enc"
            with open(corrupted_file, 'w') as f:
                json.dump({"salt": "invalid", "encrypted_seed": "invalid"}, f)

            # Try to load corrupted seed - will fail during decryption
            # The error should not include the file path
            with pytest.raises(ValueError) as exc_info:
                store.load_seed("corrupted")

            error_msg = str(exc_info.value)
            # Should not contain file path
            assert temp_dir not in error_msg
            assert corrupted_file not in error_msg
            # Should have generic message with exception type
            assert "Failed to load seed" in error_msg

    def test_pem_error_sanitization(self):
        """Ensure PEM errors don't leak library details (Issue #14)"""
        malformed_pems = [
            "-----BEGIN PRIVATE KEY-----\nINVALID\n-----END PRIVATE KEY-----",
            "not-pem-at-all",
            "-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----",
        ]

        for pem in malformed_pems:
            with pytest.raises(ValueError) as exc_info:
                AgentIdentity.from_pem(pem)

            error_msg = str(exc_info.value)
            # Should not contain library internals
            assert "asn1" not in error_msg.lower()
            assert ".c:" not in error_msg
            # Should have controlled message
            assert "Invalid PEM" in error_msg

    def test_error_message_preservation_regression(self):
        """Ensure we preserve our own error messages while sanitizing library errors"""
        import os
        import base64
        from didlite.keystore import EnvKeyStore

        # Test 1: JWS segment validation details are preserved
        with pytest.raises(ValueError, match="expected 3 segments.*got 1"):
            verify_jws("invalid")

        # Test 2: Seed size validation is preserved in EnvKeyStore
        store = EnvKeyStore()
        os.environ["DIDLITE_SEED_SIZE"] = base64.b64encode(b"a" * 16).decode()
        try:
            with pytest.raises(ValueError, match="Stored seed must be 32 bytes"):
                store.load_seed("size")
        finally:
            del os.environ["DIDLITE_SEED_SIZE"]

        # Test 3: DID validation details are preserved
        with pytest.raises(ValueError, match="Invalid DID format.*Must start with did:key:"):
            resolve_did_to_key("not-a-did")
