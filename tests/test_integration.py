"""Integration tests for compatibility with authlib

This test suite validates that didlite tokens and keys are interoperable
with authlib, a widely-used JWT/JWS library with full EdDSA/Ed25519 support.
"""

import json
from authlib.jose import JsonWebSignature, JsonWebKey
from didlite.core import AgentIdentity
from didlite.jws import create_jws, verify_jws


class TestAuthlibIntegration:
    """Test integration with authlib library"""

    def test_didlite_token_verified_by_authlib(self):
        """Test that tokens created by didlite can be verified by authlib"""
        # Create identity and token with didlite
        agent = AgentIdentity()
        payload = {"message": "Hello from didlite", "value": 999}
        token = create_jws(agent, payload)

        # Export public key as JWK for authlib
        jwk_dict = agent.to_jwk(include_private=False)

        # Convert to authlib JWK
        authlib_key = JsonWebKey.import_key(jwk_dict)

        # Verify with authlib
        jws_authlib = JsonWebSignature()
        verified_data = jws_authlib.deserialize_compact(token, authlib_key)

        # Parse payload
        verified_payload = json.loads(verified_data["payload"])
        assert verified_payload["message"] == "Hello from didlite"
        assert verified_payload["value"] == 999

    def test_authlib_token_verified_by_didlite(self):
        """Test that tokens created by authlib can be verified by didlite"""
        # Create a didlite identity to get a valid Ed25519 key
        agent = AgentIdentity()
        jwk_dict = agent.to_jwk(include_private=True)

        # Import to authlib
        authlib_key = JsonWebKey.import_key(jwk_dict)

        # Create token with authlib
        payload = json.dumps({"message": "Hello from authlib", "id": 456})
        protected = {"alg": "EdDSA", "typ": "JWT", "kid": agent.did}

        jws_authlib = JsonWebSignature()
        token = jws_authlib.serialize_compact(protected, payload, authlib_key)

        # Verify with didlite
        _, verified = verify_jws(token.decode('utf-8') if isinstance(token, bytes) else token)
        assert verified["message"] == "Hello from authlib"
        assert verified["id"] == 456

    def test_jwk_export_to_authlib(self):
        """Test exporting didlite keys to authlib"""
        # Create identity
        seed = b"test_seed_for_authlib" + b"\x00" * 11  # 32 bytes
        agent = AgentIdentity(seed=seed)

        # Export as JWK
        jwk_dict = agent.to_jwk(include_private=True)

        # Import to authlib
        authlib_key = JsonWebKey.import_key(jwk_dict)

        # Verify the key is valid
        assert authlib_key.kty == "OKP"

        # Test that we can create and verify tokens
        jws_authlib = JsonWebSignature()
        payload = json.dumps({"test": "authlib key"})
        protected = {"alg": "EdDSA"}

        token = jws_authlib.serialize_compact(protected, payload, authlib_key)
        verified_data = jws_authlib.deserialize_compact(token, authlib_key)

        assert json.loads(verified_data["payload"])["test"] == "authlib key"

    def test_jwk_roundtrip_authlib(self):
        """Test that keys exported to authlib and reimported work correctly"""
        # Create original identity
        agent1 = AgentIdentity()
        message = {"data": "roundtrip test", "count": 789}

        # Create token with didlite
        token1 = create_jws(agent1, message)

        # Export key
        jwk_dict = agent1.to_jwk(include_private=True)

        # Import to authlib and back
        authlib_key = JsonWebKey.import_key(jwk_dict)
        exported_jwk = authlib_key.as_dict(is_private=True)

        # Reimport to didlite
        agent2 = AgentIdentity.from_jwk(exported_jwk)

        # Verify token with reimported key
        _, verified = verify_jws(token1)
        assert verified["data"] == "roundtrip test"
        assert verified["count"] == 789

        # Both agents should have same DID
        assert agent1.did == agent2.did


class TestJWKRoundtrip:
    """Test JWK export/import roundtrip within didlite"""

    def test_jwk_roundtrip_consistency(self):
        """Test that keys exported and reimported produce consistent signatures"""
        # Create original identity
        agent1 = AgentIdentity()
        message = {"test": "data", "number": 42}

        # Create token with didlite
        token1 = create_jws(agent1, message)

        # Export key
        jwk_dict = agent1.to_jwk(include_private=True)

        # Reimport key to new didlite identity
        agent2 = AgentIdentity.from_jwk(jwk_dict)

        # Verify token with reimported key
        _, verified = verify_jws(token1)
        assert verified["test"] == "data"
        assert verified["number"] == 42

        # Both agents should have same DID
        assert agent1.did == agent2.did

        # Both should produce identical signatures
        test_message = b"Consistency test"
        sig1 = agent1.sign(test_message)
        sig2 = agent2.sign(test_message)
        assert sig1 == sig2
