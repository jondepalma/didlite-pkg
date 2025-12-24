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
