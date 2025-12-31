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
        _, verified_payload = verify_jws(token)

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
        _, verified = verify_jws(token)

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
        _, verified = verify_jws(token)
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
            _, verified = verify_jws(token)
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
        _, verified = verify_jws(token)

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
        _, verified_data = verify_jws(token)

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

        _, verified = verify_jws(token)

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
        _, verified = verify_jws(token)
        assert 'iat' in verified

    def test_expires_in_parameter(self):
        """Test creating token with expires_in parameter"""
        agent = AgentIdentity()
        payload = {"msg": "test"}
        expires_in = 3600  # 1 hour

        before_time = int(time.time())
        token = create_jws(agent, payload, expires_in=expires_in)
        after_time = int(time.time())

        _, verified = verify_jws(token)

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
        _, verified = verify_jws(token)

        assert 'exp' in verified
        assert verified['exp'] == exp_time

    def test_exp_takes_precedence_over_expires_in(self):
        """Test that exp parameter takes precedence over expires_in"""
        agent = AgentIdentity()
        payload = {"msg": "test"}
        expires_in = 3600
        exp_time = int(time.time()) + 7200

        token = create_jws(agent, payload, expires_in=expires_in, exp=exp_time)
        _, verified = verify_jws(token)

        # exp should match the explicit exp parameter, not iat + expires_in
        assert verified['exp'] == exp_time

    def test_valid_token_with_future_expiration(self):
        """Test that token with future expiration verifies successfully"""
        agent = AgentIdentity()
        payload = {"msg": "test"}

        token = create_jws(agent, payload, expires_in=3600)
        _, verified = verify_jws(token)

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
        _, verified = verify_jws(token)

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
            _, verified = verify_jws(token)
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

        _, verified = verify_jws(token)
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
        _, verified = verify_jws(token)

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
        _, verified_1h = verify_jws(token_1h)
        _, verified_1d = verify_jws(token_1d)
        _, verified_no_exp = verify_jws(token_no_exp)

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
        _, verified = verify_jws(token)

        # The auto-generated iat should be recent, not 12345
        assert verified['iat'] > 1700000000  # Sanity check (after 2023)
        assert verified['iat'] != 12345

        # The exp should be iat + 3600, not 67890
        assert verified['exp'] == verified['iat'] + 3600
        assert verified['exp'] != 67890


class TestPhase5SecurityRegressions:
    """
    Regression tests for Phase 5 security fixes (VULN-4, VULN-5, VULN-6)

    These tests ensure the security vulnerabilities identified in Phase 5
    do not regress in future versions.

    References:
    - PHASE_5_FINDINGS.md
    - Issues #36 (VULN-4), #37 (VULN-5), #38 (VULN-6)
    """

    def test_vuln4_algorithm_enforcement_none_algorithm_attack(self):
        """
        VULN-4: Test that 'none' algorithm is rejected (Issue #36)

        Prevents the classic "None Algorithm" JWT attack where an attacker
        removes the signature and sets alg='none'.
        """
        agent = AgentIdentity()
        payload = {"msg": "test"}
        token = create_jws(agent, payload)

        # Manually craft a token with alg='none'
        segments = token.split('.')
        header = {
            "alg": "none",
            "typ": "JWT",
            "kid": agent.did
        }

        fake_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b'=').decode()

        fake_token = f"{fake_header}.{segments[1]}.{segments[2]}"

        with pytest.raises(ValueError, match="Invalid algorithm: expected 'EdDSA', got 'none'"):
            verify_jws(fake_token)

    def test_vuln4_algorithm_substitution_attack(self):
        """
        VULN-4: Test that other algorithms are rejected (Issue #36)

        Prevents algorithm substitution attacks (e.g., RS256, HS256).
        """
        agent = AgentIdentity()
        payload = {"msg": "test"}
        token = create_jws(agent, payload)

        segments = token.split('.')

        # Test various algorithm substitutions
        malicious_algorithms = ["RS256", "HS256", "ES256", "PS256", "NONE", "EdDSA "]

        for bad_alg in malicious_algorithms:
            header = {
                "alg": bad_alg,
                "typ": "JWT",
                "kid": agent.did
            }

            fake_header = base64.urlsafe_b64encode(
                json.dumps(header, separators=(',', ':')).encode()
            ).rstrip(b'=').decode()

            fake_token = f"{fake_header}.{segments[1]}.{segments[2]}"

            with pytest.raises(ValueError, match=f"Invalid algorithm: expected 'EdDSA', got '{bad_alg}'"):
                verify_jws(fake_token)

    def test_vuln4_missing_algorithm_field(self):
        """
        VULN-4: Test that missing 'alg' field is rejected (Issue #36)
        """
        agent = AgentIdentity()
        payload = {"msg": "test"}
        token = create_jws(agent, payload)

        segments = token.split('.')
        header = {
            "typ": "JWT",
            "kid": agent.did
            # Missing 'alg' field
        }

        fake_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b'=').decode()

        fake_token = f"{fake_header}.{segments[1]}.{segments[2]}"

        with pytest.raises(ValueError, match="Invalid algorithm: expected 'EdDSA', got 'None'"):
            verify_jws(fake_token)

    def test_vuln5_compact_json_no_whitespace(self):
        """
        VULN-5: Test that JWT uses compact JSON serialization (Issue #37)

        RFC 7515 requires compact JSON (no whitespace) for JWS.
        """
        agent = AgentIdentity()
        payload = {"key1": "value1", "key2": "value2", "nested": {"a": "b"}}
        token = create_jws(agent, payload)

        # Decode header and payload
        header_b64, payload_b64, _ = token.split('.')

        # Decode to raw JSON strings
        header_json = base64.urlsafe_b64decode(header_b64 + "==").decode('utf-8')
        payload_json = base64.urlsafe_b64decode(payload_b64 + "==").decode('utf-8')

        # Verify no whitespace in JSON (compact serialization)
        assert ' ' not in header_json, "Header JSON should not contain spaces"
        assert '\n' not in header_json, "Header JSON should not contain newlines"
        assert '\t' not in header_json, "Header JSON should not contain tabs"

        assert ' ' not in payload_json, "Payload JSON should not contain spaces"
        assert '\n' not in payload_json, "Payload JSON should not contain newlines"
        assert '\t' not in payload_json, "Payload JSON should not contain tabs"

        # Verify it uses compact separators
        assert ',' in header_json, "Should use comma separator"
        assert ':' in header_json, "Should use colon separator"
        assert ', ' not in header_json, "Should not have space after comma"
        assert ': ' not in header_json, "Should not have space after colon"

    def test_vuln6_future_dated_token_rejected(self):
        """
        VULN-6: Test that tokens issued in the future are rejected (Issue #38)

        Prevents replay attacks with pre-generated future tokens.
        """
        agent = AgentIdentity()
        payload = {"msg": "test"}

        # Create token with iat 2 hours in the future (beyond clock skew)
        future_iat = int(time.time()) + 7200

        # Manually create token with future iat
        payload_with_future_iat = payload.copy()
        payload_with_future_iat['iat'] = future_iat

        header = {
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": agent.did
        }

        b64_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b'=')
        b64_payload = base64.urlsafe_b64encode(
            json.dumps(payload_with_future_iat, separators=(',', ':')).encode()
        ).rstrip(b'=')

        signing_input = b64_header + b'.' + b64_payload
        signature = agent.sign(signing_input)
        b64_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')

        future_token = (signing_input + b'.' + b64_signature).decode('utf-8')

        with pytest.raises(ValueError, match="Token issued in the future"):
            verify_jws(future_token)

    def test_vuln6_clock_skew_tolerance(self):
        """
        VULN-6: Test that clock skew tolerance works (Issue #38)

        Tokens issued up to 60 seconds in the future should be accepted
        to handle clock drift in distributed systems.
        """
        agent = AgentIdentity()
        payload = {"msg": "test"}

        # Create token with iat 30 seconds in the future (within tolerance)
        slightly_future_iat = int(time.time()) + 30

        payload_with_skew = payload.copy()
        payload_with_skew['iat'] = slightly_future_iat

        header = {
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": agent.did
        }

        b64_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b'=')
        b64_payload = base64.urlsafe_b64encode(
            json.dumps(payload_with_skew, separators=(',', ':')).encode()
        ).rstrip(b'=')

        signing_input = b64_header + b'.' + b64_payload
        signature = agent.sign(signing_input)
        b64_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')

        skewed_token = (signing_input + b'.' + b64_signature).decode('utf-8')

        # Should accept token within clock skew tolerance
        _, verified = verify_jws(skewed_token)
        assert verified['msg'] == 'test'

    def test_vuln6_past_iat_accepted(self):
        """
        VULN-6: Test that past iat values are accepted (Issue #38)

        Tokens issued in the past should always be accepted.
        """
        agent = AgentIdentity()
        payload = {"msg": "test"}

        # Create token with iat 1 hour in the past
        past_iat = int(time.time()) - 3600

        payload_with_past_iat = payload.copy()
        payload_with_past_iat['iat'] = past_iat

        header = {
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": agent.did
        }

        b64_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b'=')
        b64_payload = base64.urlsafe_b64encode(
            json.dumps(payload_with_past_iat, separators=(',', ':')).encode()
        ).rstrip(b'=')

        signing_input = b64_header + b'.' + b64_payload
        signature = agent.sign(signing_input)
        b64_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')

        past_token = (signing_input + b'.' + b64_signature).decode('utf-8')

        # Should accept token with past iat
        _, verified = verify_jws(past_token)
        assert verified['msg'] == 'test'
        assert verified['iat'] == past_iat

    def test_vuln6_missing_iat_backward_compat(self):
        """
        VULN-6: Test that missing iat is accepted (Issue #38)

        Backward compatibility - tokens without iat should still verify.
        """
        agent = AgentIdentity()
        payload = {"msg": "test"}

        # Manually create token WITHOUT iat
        header = {
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": agent.did
        }

        b64_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b'=')
        b64_payload = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).rstrip(b'=')

        signing_input = b64_header + b'.' + b64_payload
        signature = agent.sign(signing_input)
        b64_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')

        no_iat_token = (signing_input + b'.' + b64_signature).decode('utf-8')

        # Should accept token without iat (backward compatibility)
        _, verified = verify_jws(no_iat_token)
        assert verified['msg'] == 'test'
        assert 'iat' not in verified

    def test_vuln6_clock_skew_boundary_exactly_60_seconds(self):
        """
        VULN-6: Test exact boundary of clock skew (60 seconds) (Issue #38)
        """
        agent = AgentIdentity()
        payload = {"msg": "test"}

        # Create token with iat exactly 60 seconds in the future (at boundary)
        boundary_iat = int(time.time()) + 60

        payload_with_boundary = payload.copy()
        payload_with_boundary['iat'] = boundary_iat

        header = {
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": agent.did
        }

        b64_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b'=')
        b64_payload = base64.urlsafe_b64encode(
            json.dumps(payload_with_boundary, separators=(',', ':')).encode()
        ).rstrip(b'=')

        signing_input = b64_header + b'.' + b64_payload
        signature = agent.sign(signing_input)
        b64_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')

        boundary_token = (signing_input + b'.' + b64_signature).decode('utf-8')

        # Should accept token at exact boundary
        _, verified = verify_jws(boundary_token)
        assert verified['msg'] == 'test'

    def test_missing_kid_header_rejected(self):
        """
        Test that JWS tokens with missing 'kid' header are rejected.

        This is a critical security check that prevents algorithm confusion attacks.
        The 'kid' field identifies which key should verify the token.

        Reference: jws.py line 180 (missing coverage)
        """
        agent = AgentIdentity()
        payload = {"msg": "test"}

        # Manually create token WITHOUT kid header
        header = {
            "alg": "EdDSA",
            "typ": "JWT"
            # No 'kid' field
        }

        b64_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b'=')
        b64_payload = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).rstrip(b'=')

        signing_input = b64_header + b'.' + b64_payload
        signature = agent.sign(signing_input)
        b64_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')

        no_kid_token = (signing_input + b'.' + b64_signature).decode('utf-8')

        # Should reject token without kid header
        with pytest.raises(ValueError, match="JWS header missing required 'kid' field"):
            verify_jws(no_kid_token)


class TestV023JWSEnhancements:
    """Regression tests for v0.2.3 JWS header enhancements (Issues #32, #43, #44)"""

    def test_issue43_custom_headers_basic(self):
        """Test Issue #43: Add custom headers parameter to create_jws()"""
        agent = AgentIdentity()
        payload = {"test": "data"}

        # Create token with custom typ header
        token = create_jws(agent, payload, headers={"typ": "custom+jwt"})

        # Verify header contains custom typ
        header_b64 = token.split('.')[0]
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += '=' * padding
        header = json.loads(base64.urlsafe_b64decode(header_b64))

        assert header["typ"] == "custom+jwt"
        assert header["alg"] == "EdDSA"
        assert header["kid"] == agent.did

    def test_issue43_ap2_plugin_mandate_header(self):
        """Test Issue #43: AP2 plugin mandate type header"""
        agent = AgentIdentity()
        payload = {"action": "transfer", "amount": 100}

        # AP2 Intent Mandate requires specific typ header
        token = create_jws(agent, payload, headers={"typ": "application/ap2-intent+jwt"})

        header, _ = verify_jws(token)
        assert header["typ"] == "application/ap2-intent+jwt"

    def test_issue43_oauth_dpop_header(self):
        """Test Issue #43: OAuth DPoP token type header"""
        agent = AgentIdentity()
        payload = {"jti": "unique-id", "htm": "POST", "htu": "https://api.example.com"}

        # OAuth DPoP requires typ: dpop+jwt
        token = create_jws(agent, payload, headers={"typ": "dpop+jwt"})

        header, _ = verify_jws(token)
        assert header["typ"] == "dpop+jwt"

    def test_issue43_siop_header(self):
        """Test Issue #43: SIOP ID token type header"""
        agent = AgentIdentity()
        payload = {"sub": agent.did, "aud": "client-id"}

        # SIOP uses custom typ
        token = create_jws(agent, payload, headers={"typ": "siop+jwt"})

        header, _ = verify_jws(token)
        assert header["typ"] == "siop+jwt"

    def test_issue43_multiple_custom_headers(self):
        """Test Issue #43: Multiple custom headers"""
        agent = AgentIdentity()
        payload = {"test": "data"}

        # Add multiple custom headers
        custom_headers = {
            "typ": "custom+jwt",
            "x-custom-field": "value",
            "version": "1.0"
        }
        token = create_jws(agent, payload, headers=custom_headers)

        header, _ = verify_jws(token)
        assert header["typ"] == "custom+jwt"
        assert header["x-custom-field"] == "value"
        assert header["version"] == "1.0"

    def test_issue43_security_critical_fields_protected(self):
        """Test Issue #43: Security-critical fields cannot be overridden"""
        agent = AgentIdentity()
        payload = {"test": "data"}

        # Attempt to override security-critical fields
        malicious_headers = {
            "alg": "none",  # Algorithm substitution attack
            "kid": "did:key:zFAKE",  # DID spoofing
            "iat": 0,  # Timestamp manipulation
            "typ": "malicious+jwt"
        }

        token = create_jws(agent, payload, headers=malicious_headers)
        header, _ = verify_jws(token)

        # Security-critical fields should NOT be overridden
        assert header["alg"] == "EdDSA"  # NOT "none"
        assert header["kid"] == agent.did  # NOT the fake DID
        assert header["iat"] != 0  # NOT the manipulated timestamp
        # Only typ should be overridden (it's safe to override)
        assert header["typ"] == "malicious+jwt"

    def test_issue43_backward_compatibility(self):
        """Test Issue #43: Backward compatibility with no headers parameter"""
        agent = AgentIdentity()
        payload = {"test": "data"}

        # Create token without headers parameter (backward compatible)
        token = create_jws(agent, payload)

        header, verified_payload = verify_jws(token)

        # Should have default headers
        assert header["alg"] == "EdDSA"
        assert header["typ"] == "JWT"
        assert header["kid"] == agent.did
        assert "iat" in header

    def test_issue43_headers_input_not_mutated(self):
        """Test Issue #43: Input headers dict is not mutated"""
        agent = AgentIdentity()
        payload = {"test": "data"}

        # Provide custom headers
        custom_headers = {"typ": "custom+jwt", "alg": "none"}
        original_headers = custom_headers.copy()

        create_jws(agent, payload, headers=custom_headers)

        # Input dict should not be mutated
        assert custom_headers == original_headers

    def test_issue32_verify_returns_tuple(self):
        """Test Issue #32: verify_jws() returns (header, payload) tuple"""
        agent = AgentIdentity()
        payload = {"test": "data"}
        token = create_jws(agent, payload)

        # Verify return type is tuple
        result = verify_jws(token)
        assert isinstance(result, tuple)
        assert len(result) == 2

        # Unpack tuple
        header, verified_payload = result
        assert isinstance(header, dict)
        assert isinstance(verified_payload, dict)

    def test_issue32_header_contains_required_fields(self):
        """Test Issue #32: Returned header contains all required fields"""
        agent = AgentIdentity()
        payload = {"test": "data"}
        token = create_jws(agent, payload)

        header, _ = verify_jws(token)

        # Required JWS header fields
        assert "alg" in header
        assert "typ" in header
        assert "kid" in header
        assert "iat" in header

        # Verify values
        assert header["alg"] == "EdDSA"
        assert header["typ"] == "JWT"
        assert header["kid"] == agent.did

    def test_issue32_ignore_header_with_underscore(self):
        """Test Issue #32: Can ignore header with _ if not needed"""
        agent = AgentIdentity()
        payload = {"message": "hello"}
        token = create_jws(agent, payload)

        # Ignore header using _
        _, verified_payload = verify_jws(token)

        assert verified_payload["message"] == "hello"

    def test_issue32_access_signer_did_from_header(self):
        """Test Issue #32: Can extract signer DID from header"""
        agent = AgentIdentity()
        payload = {"message": "hello"}
        token = create_jws(agent, payload)

        # Extract signer DID from header
        header, _ = verify_jws(token)
        signer_did = header["kid"]

        assert signer_did == agent.did

    def test_issue32_header_and_payload_independent(self):
        """Test Issue #32: Header and payload are independent dicts"""
        agent = AgentIdentity()
        payload = {"test": "data"}
        token = create_jws(agent, payload)

        header, verified_payload = verify_jws(token)

        # Modifying header should not affect payload
        header["tampered"] = "value"
        assert "tampered" not in verified_payload

        # Modifying payload should not affect header
        verified_payload["tampered"] = "value"
        # Re-verify to get fresh header
        header2, _ = verify_jws(token)
        assert "tampered" not in header2

    def test_issue44_extract_signer_did_basic(self):
        """Test Issue #44: extract_signer_did() basic functionality"""
        agent = AgentIdentity()
        payload = {"test": "data"}
        token = create_jws(agent, payload)

        # Extract DID without full verification
        from didlite.jws import extract_signer_did
        signer_did = extract_signer_did(token)

        assert signer_did == agent.did

    def test_issue44_extract_signer_did_no_verification(self):
        """Test Issue #44: extract_signer_did() does NOT verify signature"""
        agent = AgentIdentity()
        payload = {"test": "data"}
        token = create_jws(agent, payload)

        # Tamper with signature
        parts = token.split('.')
        tampered_token = parts[0] + '.' + parts[1] + '.' + 'FAKESIGNATURE'

        # extract_signer_did should still return DID (no verification)
        from didlite.jws import extract_signer_did
        signer_did = extract_signer_did(tampered_token)
        assert signer_did == agent.did

        # But verify_jws should fail
        with pytest.raises(Exception):
            verify_jws(tampered_token)

    def test_issue44_extract_signer_did_malformed_token(self):
        """Test Issue #44: extract_signer_did() rejects malformed tokens"""
        from didlite.jws import extract_signer_did

        # Wrong number of segments
        with pytest.raises(ValueError, match="Invalid JWS format"):
            extract_signer_did("only.two")

        with pytest.raises(ValueError, match="Invalid JWS format"):
            extract_signer_did("one.two.three.four")

    def test_issue44_extract_signer_did_missing_kid(self):
        """Test Issue #44: extract_signer_did() rejects token without kid"""
        agent = AgentIdentity()

        # Manually create token without kid header
        header = {"alg": "EdDSA", "typ": "JWT"}  # Missing kid
        payload = {"test": "data"}

        b64_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b'=')
        b64_payload = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).rstrip(b'=')

        signing_input = b64_header + b'.' + b64_payload
        signature = agent.sign(signing_input)
        b64_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')

        token_without_kid = (signing_input + b'.' + b64_signature).decode('utf-8')

        # Should reject token without kid
        from didlite.jws import extract_signer_did
        with pytest.raises(ValueError, match="missing 'kid' header"):
            extract_signer_did(token_without_kid)

    def test_issue44_extract_signer_did_performance(self):
        """Test Issue #44: extract_signer_did() is fast (no signature verification)"""
        import time

        agent = AgentIdentity()
        payload = {"test": "data"}
        token = create_jws(agent, payload)

        # Measure extract_signer_did performance
        from didlite.jws import extract_signer_did
        start = time.perf_counter()
        for _ in range(100):
            extract_signer_did(token)
        extract_time = time.perf_counter() - start

        # Measure verify_jws performance
        start = time.perf_counter()
        for _ in range(100):
            verify_jws(token)
        verify_time = time.perf_counter() - start

        # extract_signer_did should be significantly faster (at least 2x)
        assert extract_time < verify_time / 2

    def test_issue43_iat_in_header(self):
        """Test Issue #43: iat is now included in header as well as payload"""
        agent = AgentIdentity()
        payload = {"test": "data"}
        token = create_jws(agent, payload)

        header, verified_payload = verify_jws(token)

        # Both header and payload should have iat
        assert "iat" in header
        assert "iat" in verified_payload

        # iat values should be the same
        assert header["iat"] == verified_payload["iat"]
