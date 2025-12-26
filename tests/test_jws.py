"""Unit tests for didlite.jws module"""

import pytest
import json
import base64
import time
from didlite.core import AgentIdentity
from didlite.jws import create_jws, verify_jws
from nacl.exceptions import BadSignatureError


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

        # Original payload should be present
        assert decoded_payload["data"] == payload["data"]
        assert decoded_payload["num"] == payload["num"]
        # iat should be automatically added
        assert 'iat' in decoded_payload

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

        # Original payload fields should be present
        assert verified_payload["msg"] == payload["msg"]
        assert verified_payload["number"] == payload["number"]
        # iat should be automatically added
        assert 'iat' in verified_payload

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

        # Original payload fields should be present
        assert verified["device"] == payload["device"]
        assert verified["metrics"] == payload["metrics"]
        assert verified["tags"] == payload["tags"]
        # iat should be automatically added
        assert 'iat' in verified

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

        with pytest.raises(BadSignatureError):
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

        with pytest.raises(BadSignatureError):
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
        assert verified["msg"] == payload["msg"]
        assert 'iat' in verified

        # But if we manually swap the DID in the header, it should fail
        header_b64, payload_b64, sig = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
        header["kid"] = agent2.did  # Claim it was signed by agent2

        fake_header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()

        fake_token = f"{fake_header_b64}.{payload_b64}.{sig}"

        with pytest.raises(BadSignatureError):
            verify_jws(fake_token)

    def test_verify_malformed_token(self):
        """Test that malformed tokens fail gracefully"""
        with pytest.raises(ValueError, match="expected 3 segments"):
            verify_jws("not.a.valid.token.structure")

    def test_verify_missing_parts(self):
        """Test that tokens with missing parts fail"""
        with pytest.raises(ValueError, match="expected 3 segments"):
            verify_jws("only.two")

    def test_verify_empty_token(self):
        """Test that empty token fails"""
        with pytest.raises(ValueError, match="expected 3 segments"):
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
            # Original payload fields should be present
            assert verified["agent"] == expected_payload["agent"]
            assert verified["data"] == expected_payload["data"]
            # iat should be automatically added
            assert 'iat' in verified

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

        # Check all original payload fields are present with correct types
        assert verified["string"] == payload["string"]
        assert verified["number"] == payload["number"]
        assert verified["float"] == payload["float"]
        assert verified["bool"] == payload["bool"]
        assert verified["null"] == payload["null"]
        assert verified["array"] == payload["array"]
        assert verified["object"] == payload["object"]

        # Verify data types are preserved
        assert isinstance(verified["string"], str)
        assert isinstance(verified["number"], int)
        assert isinstance(verified["float"], float)
        assert isinstance(verified["bool"], bool)
        assert verified["null"] is None
        assert isinstance(verified["array"], list)
        assert isinstance(verified["object"], dict)

        # iat should be automatically added
        assert 'iat' in verified
        assert isinstance(verified["iat"], int)


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


class TestJWSTTLExpiration:
    """Tests for TTL (Time-To-Live) expiration functionality"""

    def test_iat_claim_added_automatically(self):
        """Test that 'iat' (issued at) claim is automatically added"""
        agent = AgentIdentity()
        payload = {"msg": "test"}

        before_time = int(time.time())
        token = create_jws(agent, payload)
        after_time = int(time.time())

        verified = verify_jws(token)

        # iat should be present and within reasonable range
        assert 'iat' in verified
        assert before_time <= verified['iat'] <= after_time

    def test_iat_does_not_mutate_original_payload(self):
        """Test that adding 'iat' doesn't mutate the original payload"""
        agent = AgentIdentity()
        payload = {"msg": "test"}

        # Store original keys
        original_keys = set(payload.keys())

        token = create_jws(agent, payload)

        # Original payload should not be modified
        assert set(payload.keys()) == original_keys
        assert 'iat' not in payload

        # But the token should have iat
        verified = verify_jws(token)
        assert 'iat' in verified

    def test_expires_in_parameter(self):
        """Test creating token with expires_in parameter"""
        agent = AgentIdentity()
        payload = {"msg": "test"}
        expires_in = 3600  # 1 hour

        before_time = int(time.time())
        token = create_jws(agent, payload, expires_in=expires_in)
        after_time = int(time.time())

        verified = verify_jws(token)

        # exp should be iat + expires_in
        assert 'exp' in verified
        assert 'iat' in verified
        expected_exp = verified['iat'] + expires_in
        assert verified['exp'] == expected_exp

        # Sanity check: exp should be in the future
        assert verified['exp'] > after_time

    def test_exp_parameter(self):
        """Test creating token with absolute exp parameter"""
        agent = AgentIdentity()
        payload = {"msg": "test"}
        exp_time = int(time.time()) + 7200  # 2 hours from now

        token = create_jws(agent, payload, exp=exp_time)
        verified = verify_jws(token)

        assert 'exp' in verified
        assert verified['exp'] == exp_time

    def test_exp_takes_precedence_over_expires_in(self):
        """Test that exp parameter takes precedence over expires_in"""
        agent = AgentIdentity()
        payload = {"msg": "test"}
        expires_in = 3600
        exp_time = int(time.time()) + 7200

        token = create_jws(agent, payload, expires_in=expires_in, exp=exp_time)
        verified = verify_jws(token)

        # exp should match the explicit exp parameter, not iat + expires_in
        assert verified['exp'] == exp_time

    def test_valid_token_with_future_expiration(self):
        """Test that token with future expiration verifies successfully"""
        agent = AgentIdentity()
        payload = {"msg": "test"}

        token = create_jws(agent, payload, expires_in=3600)
        verified = verify_jws(token)

        assert verified['msg'] == 'test'

    def test_expired_token_fails_verification(self):
        """Test that expired token fails verification"""
        agent = AgentIdentity()
        payload = {"msg": "test"}

        # Create token that expires in 1 second
        token = create_jws(agent, payload, expires_in=1)

        # Should verify immediately
        verify_jws(token)

        # Wait for expiration
        time.sleep(2)

        # Should now fail
        with pytest.raises(ValueError, match="Token expired"):
            verify_jws(token)

    def test_expired_token_error_message(self):
        """Test that expired token error message includes time expired"""
        agent = AgentIdentity()
        payload = {"msg": "test"}

        # Create token that expired 100 seconds ago
        past_exp = int(time.time()) - 100
        token = create_jws(agent, payload, exp=past_exp)

        with pytest.raises(ValueError) as exc_info:
            verify_jws(token)

        error_msg = str(exc_info.value)
        assert "Token expired" in error_msg
        assert "seconds ago" in error_msg

    def test_token_without_expiration_still_works(self):
        """Test backward compatibility - tokens without exp claim still verify"""
        agent = AgentIdentity()
        payload = {"msg": "test"}

        # Create token without expiration
        token = create_jws(agent, payload)
        verified = verify_jws(token)

        # Should verify successfully even though no exp claim
        assert verified['msg'] == 'test'
        assert 'iat' in verified
        # exp should not be present
        assert 'exp' not in verified

    def test_token_expiring_at_exact_boundary(self):
        """Test token expiration at exact boundary (current_time >= exp_time)"""
        agent = AgentIdentity()
        payload = {"msg": "test"}

        # Create token that expires at a specific time
        exp_time = int(time.time()) + 2
        token = create_jws(agent, payload, exp=exp_time)

        # Should verify before expiration
        verify_jws(token)

        # Wait until after expiration
        time.sleep(3)

        # Should fail after expiration
        with pytest.raises(ValueError, match="Token expired"):
            verify_jws(token)

    def test_zero_expiration_time(self):
        """Test token with expires_in=0 (expires immediately)"""
        agent = AgentIdentity()
        payload = {"msg": "test"}

        token = create_jws(agent, payload, expires_in=0)

        # Token is immediately expired (or will be in the next second)
        # May or may not verify depending on exact timing
        # But should have exp = iat
        verified = None
        try:
            verified = verify_jws(token)
        except Exception:
            pass  # Expected if time advanced

        # If it didn't fail immediately, check that exp = iat
        if verified:
            assert verified['exp'] == verified['iat']

    def test_negative_expires_in(self):
        """Test token with negative expires_in (already expired)"""
        agent = AgentIdentity()
        payload = {"msg": "test"}

        token = create_jws(agent, payload, expires_in=-100)

        # Should fail immediately
        with pytest.raises(ValueError, match="Token expired"):
            verify_jws(token)

    def test_very_long_expiration(self):
        """Test token with very long expiration (years in future)"""
        agent = AgentIdentity()
        payload = {"msg": "test"}

        # 10 years in seconds
        ten_years = 10 * 365 * 24 * 60 * 60
        token = create_jws(agent, payload, expires_in=ten_years)

        verified = verify_jws(token)
        assert verified['msg'] == 'test'
        assert verified['exp'] > int(time.time())

    def test_iot_telemetry_with_short_ttl(self):
        """Test realistic IoT scenario with short-lived telemetry tokens"""
        sensor = AgentIdentity()

        # Sensor sends telemetry with 1-hour TTL
        telemetry = {
            "sensor_id": "temp-001",
            "temperature": 24.5,
            "humidity": 65.0
        }

        token = create_jws(sensor, telemetry, expires_in=3600)

        # Server receives and verifies
        verified = verify_jws(token)

        assert verified['sensor_id'] == "temp-001"
        assert verified['temperature'] == 24.5
        assert 'iat' in verified
        assert 'exp' in verified
        assert verified['exp'] == verified['iat'] + 3600

    def test_multiple_tokens_different_expirations(self):
        """Test creating multiple tokens with different expiration times"""
        agent = AgentIdentity()

        # Create tokens with different TTLs
        token_1h = create_jws(agent, {"type": "1h"}, expires_in=3600)
        token_1d = create_jws(agent, {"type": "1d"}, expires_in=86400)
        token_no_exp = create_jws(agent, {"type": "no_exp"})

        # All should verify
        verified_1h = verify_jws(token_1h)
        verified_1d = verify_jws(token_1d)
        verified_no_exp = verify_jws(token_no_exp)

        # Check expiration times
        assert 'exp' in verified_1h
        assert 'exp' in verified_1d
        assert 'exp' not in verified_no_exp

        # 1-day token should expire later than 1-hour token
        assert verified_1d['exp'] > verified_1h['exp']

    def test_payload_with_existing_iat_and_exp(self):
        """Test behavior when payload already contains iat or exp"""
        agent = AgentIdentity()

        # User tries to manually set iat and exp (should be overridden)
        payload = {
            "msg": "test",
            "iat": 12345,  # Will be overridden
            "exp": 67890   # Will be overridden if expires_in or exp param provided
        }

        token = create_jws(agent, payload, expires_in=3600)
        verified = verify_jws(token)

        # The auto-generated iat should be recent, not 12345
        assert verified['iat'] > 1700000000  # Sanity check (after 2023)
        assert verified['iat'] != 12345

        # The exp should be iat + 3600, not 67890
        assert verified['exp'] == verified['iat'] + 3600
        assert verified['exp'] != 67890
