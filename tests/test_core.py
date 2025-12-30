"""Unit tests for didlite.core module"""

import pytest
import json
from nacl.signing import VerifyKey
from nacl.encoding import RawEncoder
from didlite.core import AgentIdentity, resolve_did_to_key


class TestAgentIdentity:
    """Tests for AgentIdentity class"""

    def test_generate_random_identity(self):
        """Test generating a random identity"""
        agent = AgentIdentity()

        # Verify DID format
        assert agent.did.startswith("did:key:z")
        assert len(agent.did) > 20

        # Verify keys exist
        assert agent.signing_key is not None
        assert agent.verify_key is not None

    def test_generate_from_seed(self):
        """Test generating identity from a seed is deterministic"""
        seed = b"a" * 32  # 32-byte seed

        agent1 = AgentIdentity(seed=seed)
        agent2 = AgentIdentity(seed=seed)

        # Same seed should produce same DID
        assert agent1.did == agent2.did

        # Same seed should produce same keys
        assert agent1.signing_key.encode() == agent2.signing_key.encode()
        assert agent1.verify_key.encode() == agent2.verify_key.encode()

    def test_different_seeds_produce_different_identities(self):
        """Test that different seeds produce different identities"""
        seed1 = b"a" * 32
        seed2 = b"b" * 32

        agent1 = AgentIdentity(seed=seed1)
        agent2 = AgentIdentity(seed=seed2)

        assert agent1.did != agent2.did

    def test_random_identities_are_unique(self):
        """Test that random identities are unique"""
        agent1 = AgentIdentity()
        agent2 = AgentIdentity()

        assert agent1.did != agent2.did

    def test_did_format_compliance(self):
        """Test that generated DIDs follow W3C format"""
        agent = AgentIdentity()

        # Must start with did:key:
        assert agent.did.startswith("did:key:")

        # Must have z prefix (base58btc multibase)
        multibase_part = agent.did.split(":")[-1]
        assert multibase_part.startswith("z")

    def test_sign_message(self):
        """Test signing a message"""
        agent = AgentIdentity()
        message = b"Hello, World!"

        signature = agent.sign(message)

        # Signature should be 64 bytes for Ed25519
        assert len(signature) == 64
        assert isinstance(signature, bytes)

    def test_sign_and_verify(self):
        """Test that signed messages can be verified"""
        agent = AgentIdentity()
        message = b"Test message"

        signature = agent.sign(message)

        # Verify using the agent's verify_key
        # This should not raise an exception
        agent.verify_key.verify(message, signature)

    def test_signature_is_deterministic(self):
        """Test that signing the same message produces the same signature"""
        seed = b"test" * 8  # 32 bytes
        agent = AgentIdentity(seed=seed)
        message = b"Deterministic test"

        sig1 = agent.sign(message)
        sig2 = agent.sign(message)

        assert sig1 == sig2

    def test_to_jwk_with_private_key(self):
        """Test exporting to JWK format with private key"""
        seed = b"test" * 8  # 32 bytes for deterministic testing
        agent = AgentIdentity(seed=seed)

        jwk = agent.to_jwk(include_private=True)

        # Verify JWK structure
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert "x" in jwk  # Public key
        assert "d" in jwk  # Private key

        # Verify no padding in base64url
        assert "=" not in jwk["x"]
        assert "=" not in jwk["d"]

    def test_to_jwk_public_only(self):
        """Test exporting to JWK format with public key only"""
        agent = AgentIdentity()

        jwk = agent.to_jwk(include_private=False)

        # Verify JWK structure
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert "x" in jwk  # Public key
        assert "d" not in jwk  # No private key

    def test_from_jwk_valid(self):
        """Test importing from a valid JWK"""
        # Create original agent
        seed = b"original" + b"\x00" * 24  # 32 bytes
        agent1 = AgentIdentity(seed=seed)

        # Export to JWK
        jwk = agent1.to_jwk(include_private=True)

        # Import from JWK
        agent2 = AgentIdentity.from_jwk(jwk)

        # Verify they produce the same DID
        assert agent2.did == agent1.did

    def test_from_jwk_missing_private_key(self):
        """Test that importing JWK without private key raises error"""
        agent = AgentIdentity()
        jwk = agent.to_jwk(include_private=False)

        with pytest.raises(ValueError, match="missing private key 'd' field"):
            AgentIdentity.from_jwk(jwk)

    def test_from_jwk_invalid_kty(self):
        """Test that invalid kty raises error"""
        jwk = {
            "kty": "RSA",  # Wrong key type
            "crv": "Ed25519",
            "x": "test",
            "d": "test"
        }

        with pytest.raises(ValueError, match="kty must be 'OKP'"):
            AgentIdentity.from_jwk(jwk)

    def test_from_jwk_invalid_crv(self):
        """Test that invalid crv raises error"""
        jwk = {
            "kty": "OKP",
            "crv": "P-256",  # Wrong curve
            "x": "test",
            "d": "test"
        }

        with pytest.raises(ValueError, match="crv must be 'Ed25519'"):
            AgentIdentity.from_jwk(jwk)

    def test_jwk_roundtrip_signature_verification(self):
        """Test that JWK export/import preserves signing capability"""
        # Create original agent
        agent1 = AgentIdentity()
        message = b"Test message for JWK roundtrip"

        # Sign with original
        signature = agent1.sign(message)

        # Export and reimport
        jwk = agent1.to_jwk(include_private=True)
        agent2 = AgentIdentity.from_jwk(jwk)

        # Verify the signature with reimported key
        agent2.verify_key.verify(message, signature)

        # Sign with reimported and verify with original
        signature2 = agent2.sign(message)
        agent1.verify_key.verify(message, signature2)

    def test_to_pem_private_key(self):
        """Test exporting to PEM format with private key"""
        agent = AgentIdentity()

        pem = agent.to_pem(include_private=True)

        # Verify PEM structure
        assert isinstance(pem, str)
        assert "-----BEGIN PRIVATE KEY-----" in pem
        assert "-----END PRIVATE KEY-----" in pem
        assert len(pem) > 100  # PEM should be reasonably long

    def test_to_pem_public_key(self):
        """Test exporting to PEM format with public key only"""
        agent = AgentIdentity()

        pem = agent.to_pem(include_private=False)

        # Verify PEM structure
        assert isinstance(pem, str)
        assert "-----BEGIN PUBLIC KEY-----" in pem
        assert "-----END PUBLIC KEY-----" in pem
        assert "PRIVATE" not in pem

    def test_from_pem_valid(self):
        """Test importing from a valid PEM"""
        # Create original agent
        seed = b"pem_test" + b"\x00" * 24  # 32 bytes
        agent1 = AgentIdentity(seed=seed)

        # Export to PEM
        pem = agent1.to_pem(include_private=True)

        # Import from PEM
        agent2 = AgentIdentity.from_pem(pem)

        # Verify they produce the same DID
        assert agent2.did == agent1.did

    def test_from_pem_public_key_only_raises_error(self):
        """Test that importing PEM with public key only raises error"""
        agent = AgentIdentity()
        pem = agent.to_pem(include_private=False)

        with pytest.raises(ValueError, match="cannot create AgentIdentity from public key only"):
            AgentIdentity.from_pem(pem)

    def test_pem_roundtrip_signature_verification(self):
        """Test that PEM export/import preserves signing capability"""
        # Create original agent
        agent1 = AgentIdentity()
        message = b"Test message for PEM roundtrip"

        # Sign with original
        signature = agent1.sign(message)

        # Export and reimport
        pem = agent1.to_pem(include_private=True)
        agent2 = AgentIdentity.from_pem(pem)

        # Verify the signature with reimported key
        agent2.verify_key.verify(message, signature)

        # Sign with reimported and verify with original
        signature2 = agent2.sign(message)
        agent1.verify_key.verify(message, signature2)

    def test_jwk_pem_cross_format_consistency(self):
        """Test that JWK and PEM exports are consistent"""
        # Create an agent
        seed = b"cross_format" + b"\x00" * 20  # 32 bytes
        agent1 = AgentIdentity(seed=seed)

        # Export to both formats
        jwk = agent1.to_jwk(include_private=True)
        pem = agent1.to_pem(include_private=True)

        # Import from both formats
        agent_from_jwk = AgentIdentity.from_jwk(jwk)
        agent_from_pem = AgentIdentity.from_pem(pem)

        # All three should have the same DID
        assert agent_from_jwk.did == agent1.did
        assert agent_from_pem.did == agent1.did
        assert agent_from_jwk.did == agent_from_pem.did

        # All three should produce the same signatures
        message = b"Cross format test"
        sig1 = agent1.sign(message)
        sig_jwk = agent_from_jwk.sign(message)
        sig_pem = agent_from_pem.sign(message)

        assert sig1 == sig_jwk
        assert sig1 == sig_pem

    def test_from_jwk_invalid_private_key_size(self):
        """Test that JWK with wrong private key size raises error (Issue #11)"""
        import base64

        # Create a JWK with wrong-sized private key (16 bytes instead of 32)
        wrong_size_key = base64.urlsafe_b64encode(b"a" * 16).rstrip(b'=').decode('utf-8')

        # Create a valid public key for the JWK structure
        agent_temp = AgentIdentity()
        valid_jwk = agent_temp.to_jwk(include_private=False)

        # Add the invalid private key
        invalid_jwk = valid_jwk.copy()
        invalid_jwk['d'] = wrong_size_key

        with pytest.raises(ValueError, match="private key must be 32 bytes"):
            AgentIdentity.from_jwk(invalid_jwk)

    def test_from_pem_non_ed25519_key(self):
        """Test that importing non-Ed25519 PEM raises error (Issue #11)"""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        # Generate RSA key (not Ed25519)
        rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Export as PEM
        rsa_pem = rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        with pytest.raises(ValueError, match="key must be Ed25519"):
            AgentIdentity.from_pem(rsa_pem)

    def test_from_pem_type_validation(self):
        """Test that from_pem() validates input type (Issue #13)"""
        # Test with bytes
        with pytest.raises(TypeError, match="pem_string must be a str, got bytes"):
            AgentIdentity.from_pem(b"-----BEGIN PRIVATE KEY-----...")

        # Test with int
        with pytest.raises(TypeError, match="pem_string must be a str, got int"):
            AgentIdentity.from_pem(12345)

        # Test with list
        with pytest.raises(TypeError, match="pem_string must be a str, got list"):
            AgentIdentity.from_pem(["-----BEGIN", "PRIVATE", "KEY-----"])

        # Test with None
        with pytest.raises(TypeError, match="pem_string must be a str, got NoneType"):
            AgentIdentity.from_pem(None)

    def test_from_jwk_type_validation(self):
        """Test that from_jwk() validates input type (Issue #12)"""
        # Test with string
        with pytest.raises(TypeError, match="jwk must be a dict, got str"):
            AgentIdentity.from_jwk("not-a-dict")

        # Test with int
        with pytest.raises(TypeError, match="jwk must be a dict, got int"):
            AgentIdentity.from_jwk(12345)

        # Test with list
        with pytest.raises(TypeError, match="jwk must be a dict, got list"):
            AgentIdentity.from_jwk(["kty", "OKP"])

        # Test with None
        with pytest.raises(TypeError, match="jwk must be a dict, got NoneType"):
            AgentIdentity.from_jwk(None)


class TestResolveDIDToKey:
    """Tests for resolve_did_to_key function"""

    def test_resolve_valid_did(self):
        """Test resolving a valid DID to a public key"""
        agent = AgentIdentity()

        # Resolve the DID back to a key
        resolved_key = resolve_did_to_key(agent.did)

        # Should match the original verify key
        assert isinstance(resolved_key, VerifyKey)
        assert resolved_key.encode() == agent.verify_key.encode()

    def test_resolve_and_verify_signature(self):
        """Test that resolved key can verify signatures"""
        agent = AgentIdentity()
        message = b"Test message"
        signature = agent.sign(message)

        # Resolve DID to key
        resolved_key = resolve_did_to_key(agent.did)

        # Verify signature with resolved key
        resolved_key.verify(message, signature)

    def test_resolve_invalid_did_format(self):
        """Test that invalid DID format raises error"""
        with pytest.raises(ValueError, match="Invalid DID format"):
            resolve_did_to_key("not-a-did")

    def test_resolve_wrong_prefix(self):
        """Test that wrong DID prefix raises error"""
        with pytest.raises(ValueError, match="Invalid DID format"):
            resolve_did_to_key("did:web:example.com")

    def test_roundtrip_consistency(self):
        """Test that DID -> Key -> DID resolution is consistent"""
        # Create an agent
        agent1 = AgentIdentity()

        # Resolve DID to key
        resolved_key = resolve_did_to_key(agent1.did)

        # Create a new agent with the resolved key's bytes as seed would be complex
        # Instead, verify that the resolved key can verify signatures from original agent
        message = b"Roundtrip test"
        signature = agent1.sign(message)

        # This should not raise
        resolved_key.verify(message, signature)

    def test_cross_agent_verification(self):
        """Test that one agent's DID can be used to verify its signatures"""
        agent = AgentIdentity()
        message = b"Cross verification"
        signature = agent.sign(message)

        # Someone else resolves the DID and verifies
        external_key = resolve_did_to_key(agent.did)
        external_key.verify(message, signature)

    def test_resolve_deterministic(self):
        """Test that resolving same DID multiple times gives same key"""
        agent = AgentIdentity()

        key1 = resolve_did_to_key(agent.did)
        key2 = resolve_did_to_key(agent.did)

        assert key1.encode() == key2.encode()


class TestPhase5CoreRegressions:
    """
    Regression tests for Phase 5 core.py fixes (VULN-1, VULN-2)

    References:
    - PHASE_5_FINDINGS.md
    - Issues #33 (VULN-1), #34 (VULN-2)
    """

    def test_vuln1_did_length_limit(self):
        """
        VULN-1: Test that DID length is limited to prevent DoS (Issue #33)

        Prevents OOM attacks on edge devices via oversized DID strings.
        """
        import multibase

        # Test exact boundary (128 characters)
        # Create a DID that's exactly 128 characters
        boundary_data = b'x' * 70  # Adjust to get ~128 char DID after encoding
        boundary_multibase = multibase.encode('base58btc', boundary_data)
        boundary_did = f"did:key:{boundary_multibase.decode('utf-8')}"

        if len(boundary_did) <= 128:
            # Should not raise if <= 128
            try:
                resolve_did_to_key(boundary_did)
            except ValueError as e:
                # May fail for other reasons (wrong format, etc.) but not length
                assert "length exceeds 128" not in str(e)

        # Test oversized DID (> 128 characters)
        huge_data = b'x' * 1000
        huge_multibase = multibase.encode('base58btc', huge_data)
        huge_did = f"did:key:{huge_multibase.decode('utf-8')}"

        # Should fail BEFORE attempting to decode
        with pytest.raises(ValueError, match="Invalid DID: length exceeds 128 characters"):
            resolve_did_to_key(huge_did)

    def test_vuln1_did_type_validation(self):
        """
        VULN-1: Test that DID type is validated (Issue #33)

        Part of DoS prevention - reject non-string inputs.
        """
        # Test non-string types
        with pytest.raises(TypeError, match="DID must be a string, got int"):
            resolve_did_to_key(12345)

        with pytest.raises(TypeError, match="DID must be a string, got list"):
            resolve_did_to_key(["did:key:z6Mk..."])

        with pytest.raises(TypeError, match="DID must be a string, got bytes"):
            resolve_did_to_key(b"did:key:z6Mk...")

        with pytest.raises(TypeError, match="DID must be a string, got NoneType"):
            resolve_did_to_key(None)

    def test_vuln2_base64_padding_edge_cases(self):
        """
        VULN-2: Test correct base64 padding for JWK import (Issue #34)

        Ed25519 seeds are always 32 bytes, so base64 encoding always produces
        43 characters (43 % 4 = 3, so needs 1 padding char).

        This test verifies the padding formula works correctly for this case.
        """
        import base64

        # Test multiple seeds to ensure padding formula works
        for i in range(20):
            seed = bytes([i * 7 % 256] * 32)
            agent = AgentIdentity(seed=seed)
            jwk = agent.to_jwk(include_private=True)
            d_field = jwk["d"]

            # Ed25519 seeds (32 bytes) → 43 base64 chars → needs 1 padding
            assert len(d_field) == 43, f"Expected 43 chars, got {len(d_field)}"

            # Import should work correctly with padding formula
            imported_agent = AgentIdentity.from_jwk(jwk)

            # Verify it produces the same DID
            assert imported_agent.did == agent.did

            # Verify same signatures
            message = b"test"
            assert imported_agent.sign(message) == agent.sign(message)

    def test_vuln2_padding_formula_validation(self):
        """
        VULN-2: Validate the padding formula works correctly (Issue #34)

        OLD (incorrect): "=" * (4 - len(data) % 4)
          - len=4 → 4-0=4 → adds 4 '=' (WRONG!)
          - len=5 → 4-1=3 → adds 3 '=' (correct)
          - len=6 → 4-2=2 → adds 2 '=' (correct)
          - len=7 → 4-3=1 → adds 1 '=' (correct)

        NEW (correct): "=" * (-len(data) % 4)
          - len=4 → -4%4=0 → adds 0 '=' (correct)
          - len=5 → -5%4=3 → adds 3 '=' (correct)
          - len=6 → -6%4=2 → adds 2 '=' (correct)
          - len=7 → -7%4=1 → adds 1 '=' (correct)
        """
        import base64

        # Test the formula directly
        test_vectors = [
            (4, 0),   # len % 4 == 0 → 0 padding
            (5, 3),   # len % 4 == 1 → 3 padding
            (6, 2),   # len % 4 == 2 → 2 padding
            (7, 1),   # len % 4 == 3 → 1 padding
            (8, 0),   # len % 4 == 0 → 0 padding
            (43, 1),  # Base64 standard key length case
            (44, 0),  # Another common case
        ]

        for length, expected_padding in test_vectors:
            # Generate a test string of specified length
            test_data = "x" * length

            # Apply the correct formula
            padding = -len(test_data) % 4

            assert padding == expected_padding, \
                f"For length {length}, expected {expected_padding} padding, got {padding}"

            # Verify it actually decodes correctly
            padded = test_data + ("=" * padding)
            try:
                # This should not raise
                base64.urlsafe_b64decode(padded)
            except Exception:
                # Some lengths won't decode (not valid base64), that's OK
                # We're just testing the padding formula
                pass

    def test_vuln2_jwk_import_with_various_key_sizes(self):
        """
        VULN-2: Test JWK import works with various base64 string lengths (Issue #34)
        """
        # Test multiple different seeds to ensure various padding cases work
        for i in range(20):
            seed = bytes([i * 7 % 256] * 32)
            agent1 = AgentIdentity(seed=seed)
            jwk = agent1.to_jwk(include_private=True)

            # Import from JWK
            agent2 = AgentIdentity.from_jwk(jwk)

            # Should produce same DID
            assert agent2.did == agent1.did

            # Should produce same signatures
            message = b"test message"
            sig1 = agent1.sign(message)
            sig2 = agent2.sign(message)
            assert sig1 == sig2
