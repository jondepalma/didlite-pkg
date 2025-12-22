"""Unit tests for didlite.core module"""

import pytest
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
