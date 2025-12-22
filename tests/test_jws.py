"""Unit tests for didlite.jws module"""

import pytest
import json
import base64
from didlite.core import AgentIdentity
from didlite.jws import create_jws, verify_jws


class TestCreateJWS:
    """Tests for create_jws function"""

    def test_create_basic_jws(self):
        """Test creating a basic JWS token"""
        agent = AgentIdentity()
        payload = {"msg": "hello"}

        token = create_jws(agent, payload)

        # Token should have 3 parts separated by dots
        parts = token.split(".")
        assert len(parts) == 3

    def test_jws_format_structure(self):
        """Test that JWS has proper structure"""
        agent = AgentIdentity()
        payload = {"test": "data"}

        token = create_jws(agent, payload)
        header_b64, payload_b64, sig_b64 = token.split(".")

        # Decode header
        header_json = base64.urlsafe_b64decode(header_b64 + "==")
        header = json.loads(header_json)

        # Verify header fields
        assert header["alg"] == "EdDSA"
        assert header["typ"] == "JWT"
        assert header["kid"] == agent.did

    def test_jws_payload_encoding(self):
        """Test that payload is correctly encoded"""
        agent = AgentIdentity()
        payload = {"data": "test", "num": 42}

        token = create_jws(agent, payload)
        _, payload_b64, _ = token.split(".")

        # Decode and verify payload
        payload_json = base64.urlsafe_b64decode(payload_b64 + "==")
        decoded_payload = json.loads(payload_json)

        assert decoded_payload == payload

    def test_jws_with_complex_payload(self):
        """Test creating JWS with complex nested payload"""
        agent = AgentIdentity()
        payload = {
            "sensor": "temp-001",
            "data": {
                "temperature": 24.5,
                "humidity": 65.3
            },
            "timestamp": 1678900000,
            "readings": [1, 2, 3, 4, 5]
        }

        token = create_jws(agent, payload)
        assert isinstance(token, str)
        assert len(token.split(".")) == 3

    def test_deterministic_signature(self):
        """Test that same payload produces same signature"""
        seed = b"deterministic" * 3  # 39 bytes, will be truncated to 32
        agent = AgentIdentity(seed=seed[:32])
        payload = {"msg": "test"}

        token1 = create_jws(agent, payload)
        token2 = create_jws(agent, payload)

        # Should be identical
        assert token1 == token2

    def test_different_agents_different_signatures(self):
        """Test that different agents produce different signatures"""
        payload = {"msg": "same message"}

        agent1 = AgentIdentity()
        agent2 = AgentIdentity()

        token1 = create_jws(agent1, payload)
        token2 = create_jws(agent2, payload)

        # Tokens should be different
        assert token1 != token2

        # But payloads should be same
        _, payload1_b64, _ = token1.split(".")
        _, payload2_b64, _ = token2.split(".")
        assert payload1_b64 == payload2_b64


class TestVerifyJWS:
    """Tests for verify_jws function"""

    def test_verify_valid_token(self):
        """Test verifying a valid token"""
        agent = AgentIdentity()
        payload = {"msg": "hello", "number": 123}

        token = create_jws(agent, payload)
        verified_payload = verify_jws(token)

        assert verified_payload == payload

    def test_verify_complex_payload(self):
        """Test verifying complex payloads"""
        agent = AgentIdentity()
        payload = {
            "device": "sensor-42",
            "metrics": {
                "temp": 24.5,
                "pressure": 1013.25
            },
            "tags": ["iot", "edge"]
        }

        token = create_jws(agent, payload)
        verified = verify_jws(token)

        assert verified == payload

    def test_verify_tampered_payload_fails(self):
        """Test that tampered payload fails verification"""
        agent = AgentIdentity()
        payload = {"msg": "original"}

        token = create_jws(agent, payload)

        # Tamper with the payload part
        header, payload_b64, signature = token.split(".")
        tampered_payload = {"msg": "tampered"}
        tampered_b64 = base64.urlsafe_b64encode(
            json.dumps(tampered_payload).encode()
        ).rstrip(b'=').decode()

        tampered_token = f"{header}.{tampered_b64}.{signature}"

        with pytest.raises(Exception, match="Verification Failed"):
            verify_jws(tampered_token)

    def test_verify_tampered_signature_fails(self):
        """Test that tampered signature fails verification"""
        agent = AgentIdentity()
        payload = {"msg": "test"}

        token = create_jws(agent, payload)
        header, payload_b64, signature = token.split(".")

        # Corrupt the signature
        corrupted_sig = signature[:-5] + "XXXXX"
        tampered_token = f"{header}.{payload_b64}.{corrupted_sig}"

        with pytest.raises(Exception, match="Verification Failed"):
            verify_jws(tampered_token)

    def test_verify_wrong_signer(self):
        """Test that token from different agent fails verification"""
        agent1 = AgentIdentity()
        agent2 = AgentIdentity()

        payload = {"msg": "test"}
        token = create_jws(agent1, payload)

        # Verification should still work because it uses the DID in the token
        # The DID in the header tells us who signed it
        verified = verify_jws(token)
        assert verified == payload

        # But if we manually swap the DID in the header, it should fail
        header_b64, payload_b64, sig = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
        header["kid"] = agent2.did  # Claim it was signed by agent2

        fake_header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()

        fake_token = f"{fake_header_b64}.{payload_b64}.{sig}"

        with pytest.raises(Exception, match="Verification Failed"):
            verify_jws(fake_token)

    def test_verify_malformed_token(self):
        """Test that malformed tokens fail gracefully"""
        with pytest.raises(Exception, match="Verification Failed"):
            verify_jws("not.a.valid.token.structure")

    def test_verify_missing_parts(self):
        """Test that tokens with missing parts fail"""
        with pytest.raises(Exception, match="Verification Failed"):
            verify_jws("only.two")

    def test_verify_empty_token(self):
        """Test that empty token fails"""
        with pytest.raises(Exception, match="Verification Failed"):
            verify_jws("")

    def test_roundtrip_multiple_agents(self):
        """Test multiple agents can create and verify tokens"""
        agents = [AgentIdentity() for _ in range(3)]
        payloads = [
            {"agent": 0, "data": "first"},
            {"agent": 1, "data": "second"},
            {"agent": 2, "data": "third"}
        ]

        # Each agent creates a token
        tokens = [create_jws(agent, payload)
                  for agent, payload in zip(agents, payloads)]

        # All tokens should verify correctly
        for token, expected_payload in zip(tokens, payloads):
            verified = verify_jws(token)
            assert verified == expected_payload

    def test_verify_preserves_data_types(self):
        """Test that verification preserves data types"""
        agent = AgentIdentity()
        payload = {
            "string": "hello",
            "number": 42,
            "float": 3.14,
            "bool": True,
            "null": None,
            "array": [1, 2, 3],
            "object": {"nested": "value"}
        }

        token = create_jws(agent, payload)
        verified = verify_jws(token)

        assert verified == payload
        assert isinstance(verified["string"], str)
        assert isinstance(verified["number"], int)
        assert isinstance(verified["float"], float)
        assert isinstance(verified["bool"], bool)
        assert verified["null"] is None
        assert isinstance(verified["array"], list)
        assert isinstance(verified["object"], dict)


class TestJWSIntegration:
    """Integration tests for JWS functionality"""

    def test_end_to_end_iot_scenario(self):
        """Test realistic IoT sensor scenario"""
        # Device generates identity
        sensor = AgentIdentity()
        sensor_id = sensor.did

        # Device sends telemetry
        telemetry = {
            "device_id": sensor_id,
            "temp": 24.5,
            "humidity": 65.0,
            "timestamp": 1678900000
        }
        token = create_jws(sensor, telemetry)

        # Server receives and verifies
        verified_data = verify_jws(token)

        assert verified_data["device_id"] == sensor_id
        assert verified_data["temp"] == 24.5

    def test_persistent_identity_scenario(self):
        """Test that persistent identity works across 'reboots'"""
        seed = b"secret_device_key_stored_securely!!"[:32]

        # First boot
        device1 = AgentIdentity(seed=seed)
        did1 = device1.did
        token1 = create_jws(device1, {"boot": 1})

        # Simulated reboot - recreate from same seed
        device2 = AgentIdentity(seed=seed)
        did2 = device2.did

        # Should have same DID
        assert did1 == did2

        # Both tokens should verify
        verify_jws(token1)
        token2 = create_jws(device2, {"boot": 2})
        verify_jws(token2)
