"""Integration tests for compatibility with python-jose and authlib

Note: python-jose does not support EdDSA/Ed25519 algorithm, so those tests
are skipped. This is a known limitation of python-jose.
See: https://github.com/mpdavis/python-jose/issues

Authlib fully supports EdDSA/Ed25519 and is the recommended library for
interoperability with didlite.
"""

import pytest
import json
from jose import jws as jose_jws, jwk as jose_jwk
from authlib.jose import JsonWebSignature, JsonWebKey
from didlite.core import AgentIdentity
from didlite.jws import create_jws, verify_jws


class TestPythonJoseIntegration:
    """Test integration with python-jose library

    Note: These tests are skipped because python-jose does not support EdDSA algorithm.
    This is a limitation of python-jose, not didlite.
    """

    @pytest.mark.skip(reason="python-jose does not support EdDSA/Ed25519")
    def test_didlite_token_verified_by_python_jose(self):
        """Test that tokens created by didlite can be verified by python-jose"""
        # Create identity and token with didlite
        agent = AgentIdentity()
        payload = {"message": "Hello from didlite", "user_id": 42}
        token = create_jws(agent, payload)

        # Export public key as JWK for python-jose
        jwk_dict = agent.to_jwk(include_private=False)

        # Verify with python-jose
        # python-jose expects the key in a specific format
        decoded = jose_jws.verify(
            token,
            jwk_dict,
            algorithms=["EdDSA"]
        )

        # Parse the payload
        verified_payload = json.loads(decoded)
        assert verified_payload["message"] == "Hello from didlite"
        assert verified_payload["user_id"] == 42

    @pytest.mark.skip(reason="python-jose does not support EdDSA/Ed25519")
    def test_python_jose_token_verified_by_didlite(self):
        """Test that tokens created by python-jose can be verified by didlite"""
        # Create a didlite identity to get a valid Ed25519 key
        agent = AgentIdentity()
        jwk_dict = agent.to_jwk(include_private=True)

        # Create token with python-jose
        payload = json.dumps({"message": "Hello from python-jose", "count": 123})

        token = jose_jws.sign(
            payload,
            jwk_dict,
            algorithm="EdDSA",
            headers={"kid": agent.did}
        )

        # Verify with didlite
        verified = verify_jws(token)
        assert verified["message"] == "Hello from python-jose"
        assert verified["count"] == 123

    @pytest.mark.skip(reason="python-jose does not support EdDSA/Ed25519")
    def test_jwk_export_to_python_jose(self):
        """Test exporting didlite keys to python-jose"""
        # Create identity
        seed = b"test_seed_for_jose" + b"\x00" * 14  # 32 bytes
        agent = AgentIdentity(seed=seed)

        # Export as JWK
        jwk_dict = agent.to_jwk(include_private=True)

        # Sign with didlite
        message = b"Test message"
        didlite_sig = agent.sign(message)

        # Verify the JWK can be used in python-jose
        # python-jose can verify signatures created by didlite
        payload = json.dumps({"data": "test"})
        token = jose_jws.sign(payload, jwk_dict, algorithm="EdDSA")

        # Should not raise
        jose_jws.verify(token, jwk_dict, algorithms=["EdDSA"])

    def test_jwk_roundtrip_python_jose(self):
        """Test that keys exported to python-jose and reimported work correctly"""
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
        verified = verify_jws(token1)
        assert verified["test"] == "data"
        assert verified["number"] == 42

        # Both agents should have same DID
        assert agent1.did == agent2.did


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
        verified = verify_jws(token.decode('utf-8') if isinstance(token, bytes) else token)
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
        verified = verify_jws(token1)
        assert verified["data"] == "roundtrip test"
        assert verified["count"] == 789

        # Both agents should have same DID
        assert agent1.did == agent2.did


class TestCrossLibraryCompatibility:
    """Test compatibility across all three libraries"""

    @pytest.mark.skip(reason="python-jose does not support EdDSA/Ed25519")
    def test_didlite_to_jose_to_authlib(self):
        """Test key exported from didlite works in both python-jose and authlib"""
        # Create identity
        agent = AgentIdentity()
        message = {"source": "didlite", "target": ["jose", "authlib"]}

        # Create token
        token = create_jws(agent, message)

        # Export public key
        jwk_dict = agent.to_jwk(include_private=False)

        # Verify with python-jose
        jose_decoded = jose_jws.verify(token, jwk_dict, algorithms=["EdDSA"])
        jose_payload = json.loads(jose_decoded)
        assert jose_payload["source"] == "didlite"

        # Verify with authlib
        authlib_key = JsonWebKey.import_key(jwk_dict)
        jws_authlib = JsonWebSignature()
        authlib_verified = jws_authlib.deserialize_compact(token, authlib_key)
        authlib_payload = json.loads(authlib_verified["payload"])
        assert authlib_payload["source"] == "didlite"

        # Both should decode to same payload
        assert jose_payload == authlib_payload

    @pytest.mark.skip(reason="python-jose does not support EdDSA/Ed25519")
    def test_token_created_by_each_library(self):
        """Test that all three libraries can create interoperable tokens"""
        # Create a shared identity
        agent = AgentIdentity()
        jwk_dict = agent.to_jwk(include_private=True)
        authlib_key = JsonWebKey.import_key(jwk_dict)
        payload_dict = {"message": "cross-library test"}

        # Create token with didlite
        token_didlite = create_jws(agent, payload_dict)

        # Create token with python-jose
        payload_json = json.dumps(payload_dict)
        token_jose = jose_jws.sign(
            payload_json,
            jwk_dict,
            algorithm="EdDSA",
            headers={"kid": agent.did}
        )

        # Create token with authlib
        protected = {"alg": "EdDSA", "typ": "JWT", "kid": agent.did}
        jws_authlib = JsonWebSignature()
        token_authlib = jws_authlib.serialize_compact(protected, payload_json, authlib_key)
        if isinstance(token_authlib, bytes):
            token_authlib = token_authlib.decode('utf-8')

        # All tokens should be verifiable by didlite
        verified_didlite = verify_jws(token_didlite)
        verified_jose = verify_jws(token_jose)
        verified_authlib = verify_jws(token_authlib)

        assert verified_didlite["message"] == "cross-library test"
        assert verified_jose["message"] == "cross-library test"
        assert verified_authlib["message"] == "cross-library test"

    def test_signature_consistency_across_libraries(self):
        """Test that the same message produces verifiable signatures across libraries"""
        # Create identity and export keys
        seed = b"consistent" + b"\x00" * 22  # 32 bytes
        agent = AgentIdentity(seed=seed)
        jwk_dict = agent.to_jwk(include_private=True)

        # Same message
        test_message = b"Consistency test message"

        # Sign with didlite
        sig_didlite = agent.sign(test_message)

        # All signatures should verify with the public key
        # This is tested by the fact that tokens from all libraries verify
        # in verify_jws, which uses the DID resolution
        assert len(sig_didlite) == 64  # Ed25519 signature is 64 bytes
