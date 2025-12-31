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

from __future__ import annotations

import time
import json
import base64
from .core import AgentIdentity, resolve_did_to_key
from nacl.exceptions import BadSignatureError


def _b64url_decode(data: str) -> bytes:
    """
    Decode base64url-encoded data with proper padding calculation.

    Base64 encoding requires padding to multiples of 4 characters.
    This function calculates the correct padding needed.

    Args:
        data: Base64url-encoded string (without padding)

    Returns:
        Decoded bytes

    Reference:
        RFC 4648 (Base64 encoding): https://tools.ietf.org/html/rfc4648
        SECURITY_FINDINGS.md HIGH-2, Issue #7
    """
    # Calculate padding needed (0-3 '=' chars)
    padding_needed = (4 - len(data) % 4) % 4
    padded_data = data + ('=' * padding_needed)
    return base64.urlsafe_b64decode(padded_data)

def create_jws(agent: AgentIdentity, payload: dict, expires_in: int = None, exp: int = None, headers: dict = None) -> str:
    """
    Creates a compact JWS (JSON Web Signature).
    Similar to a JWT but signed with Ed25519.

    Args:
        agent: The AgentIdentity to sign with
        payload: The payload data to include in the token
        expires_in: Optional time-to-live in seconds (e.g., 3600 for 1 hour)
        exp: Optional absolute expiration time as Unix timestamp
        headers: Optional custom headers to merge with default headers

    Returns:
        A compact JWS token string

    Note:
        If both expires_in and exp are provided, exp takes precedence.
        The token automatically includes 'iat' (issued at) claim in both header and payload.
        Custom headers will override defaults (except 'alg', 'kid', and 'iat' which are protected).

    Examples:
        # AP2 Plugin - Intent Mandate
        token = create_jws(agent, payload, headers={"typ": "application/ap2-intent+jwt"})

        # OAuth Plugin - DPoP token
        token = create_jws(agent, payload, headers={"typ": "dpop+jwt"})

        # SIOP Plugin - SIOP ID token
        token = create_jws(agent, payload, headers={"typ": "siop+jwt"})
    """
    # Make a copy to avoid mutating the original payload
    payload_copy = payload.copy()

    # Add 'iat' (issued at) claim to all tokens for audit trail
    current_time = int(time.time())
    payload_copy['iat'] = current_time

    # Add expiration if specified
    if exp is not None:
        payload_copy['exp'] = exp
    elif expires_in is not None:
        payload_copy['exp'] = current_time + expires_in

    # Build default header
    header = {
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": agent.did,
        "iat": current_time
    }

    # Merge custom headers if provided
    # Custom headers can override 'typ' but NOT 'alg', 'kid', or 'iat' (security-critical)
    if headers:
        # Make a copy to avoid mutating the input
        custom_headers = headers.copy()

        # Remove any attempt to override security-critical fields
        custom_headers.pop('alg', None)
        custom_headers.pop('kid', None)
        custom_headers.pop('iat', None)

        # Merge remaining custom headers (typ and any others)
        header.update(custom_headers)

    # Base64URL Encode Header & Payload
    # SECURITY: Use compact JSON serialization (RFC 7515 compliance)
    # Reference: PHASE_5 VULN-5, Issue #37
    b64_header = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).rstrip(b'=')
    b64_payload = base64.urlsafe_b64encode(json.dumps(payload_copy, separators=(',', ':')).encode()).rstrip(b'=')

    # Create Signing Input
    signing_input = b64_header + b'.' + b64_payload

    # Sign
    signature = agent.sign(signing_input)
    b64_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')

    return (signing_input + b'.' + b64_signature).decode('utf-8')

def verify_jws(token: str) -> tuple[dict, dict]:
    """
    Verifies a JWS token and returns both header and payload.

    Args:
        token: The compact JWS token string to verify

    Returns:
        tuple[dict, dict]: (header, payload) where:
            - header: dict containing alg, typ, kid, iat, etc.
            - payload: dict containing the verified claims

    Raises:
        ValueError: Token format is invalid, expired, or DID is invalid
        BadSignatureError: Signature verification failed
        json.JSONDecodeError: Header or payload contains invalid JSON

    Examples:
        # Get both header and payload
        header, payload = verify_jws(token)
        signer_did = header['kid']
        message = payload['message']

        # Ignore header if you don't need it
        _, payload = verify_jws(token)
        message = payload['message']

    Note:
        This is a breaking change from v0.2.2 which returned only the payload.
        See VERIFY_JWS_CHANGE.md for migration guide.
    """
    # SECURITY: Validate token format before unpacking
    # Reference: SECURITY_FINDINGS.md HIGH-1, Issue #6
    segments = token.split('.')
    if len(segments) != 3:
        raise ValueError(
            f"Invalid JWS format: expected 3 segments (header.payload.signature), "
            f"got {len(segments)}"
        )

    header_segment, payload_segment, crypto_segment = segments

    # 1. Decode Header to find the 'kid' (Key ID / DID)
    header_data = _b64url_decode(header_segment)
    header = json.loads(header_data)

    # SECURITY: Enforce EdDSA algorithm (prevent "None Algorithm" attacks)
    # Reference: PHASE_5 VULN-4, Issue #36, RFC 7515 Section 3.1
    alg = header.get('alg')
    if alg != 'EdDSA':
        raise ValueError(f"Invalid algorithm: expected 'EdDSA', got '{alg}'")

    signer_did = header.get('kid')

    # SECURITY: Validate 'kid' field exists (prevents algorithm confusion attacks)
    if not signer_did:
        raise ValueError("JWS header missing required 'kid' field")

    # 2. Resolve the DID to a Public Key
    verify_key = resolve_did_to_key(signer_did)

    # 3. Verify Signature
    signing_input = (header_segment + "." + payload_segment).encode()
    signature = _b64url_decode(crypto_segment)

    verify_key.verify(signing_input, signature)

    # 4. Decode Payload
    payload_data = _b64url_decode(payload_segment)
    payload = json.loads(payload_data)

    # 5. Check Issued-At Time (if present) - prevent future-dated tokens
    # SECURITY: Future-dating protection (RFC 7519 compliance)
    # Reference: PHASE_5 VULN-6, Issue #38
    if 'iat' in payload:
        current_time = int(time.time())
        iat_time = payload['iat']

        # Allow 60-second clock skew tolerance for distributed systems
        CLOCK_SKEW_SECONDS = 60
        if iat_time > current_time + CLOCK_SKEW_SECONDS:
            future_seconds = iat_time - current_time
            raise ValueError(f"Token issued in the future (iat is {future_seconds} seconds ahead)")

    # 6. Check Expiration (if present)
    if 'exp' in payload:
        current_time = int(time.time())
        exp_time = payload['exp']

        if current_time >= exp_time:
            # Calculate how long ago it expired for better error message
            expired_seconds = current_time - exp_time
            raise ValueError(f"Token expired {expired_seconds} seconds ago")

    # 7. Return Both Header and Payload
    return (header, payload)

def extract_signer_did(token: str) -> str:
    """
    Extract the signer's DID from a JWS token without verification.

    Useful for routing, logging, and rate limiting before expensive signature verification.

    WARNING: This does NOT verify the signature. Always call verify_jws() before
    trusting the payload or making security decisions.

    Args:
        token: The JWS token string

    Returns:
        The DID from the kid header field

    Raises:
        ValueError: If token is malformed or missing kid header

    Examples:
        # Fast DID extraction for logging
        try:
            signer_did = extract_signer_did(token)
            logger.info(f"Request from {signer_did}")
        except ValueError:
            logger.warning("Malformed token received")

        # Then verify if needed
        header, payload = verify_jws(token)

    Note:
        This function is for performance optimization in routing and logging scenarios.
        It performs minimal validation and does NOT check the signature.
    """
    try:
        # Split token into segments
        segments = token.split('.')
        if len(segments) != 3:
            raise ValueError(
                f"Invalid JWS format: expected 3 segments (header.payload.signature), "
                f"got {len(segments)}"
            )

        header_segment = segments[0]

        # Decode header
        header_data = _b64url_decode(header_segment)
        header = json.loads(header_data)

        # Extract DID from kid field
        did = header.get('kid')

        if not did:
            raise ValueError("Token missing 'kid' header field")

        return did

    except (ValueError, json.JSONDecodeError, Exception) as e:
        # Normalize all errors to ValueError with descriptive message
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"Invalid JWS token: {e}")
