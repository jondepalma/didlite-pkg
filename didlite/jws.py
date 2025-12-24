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

def create_jws(agent: AgentIdentity, payload: dict, expires_in: int = None, exp: int = None) -> str:
    """
    Creates a compact JWS (JSON Web Signature).
    Similar to a JWT but signed with Ed25519.

    Args:
        agent: The AgentIdentity to sign with
        payload: The payload data to include in the token
        expires_in: Optional time-to-live in seconds (e.g., 3600 for 1 hour)
        exp: Optional absolute expiration time as Unix timestamp

    Returns:
        A compact JWS token string

    Note:
        If both expires_in and exp are provided, exp takes precedence.
        The token automatically includes 'iat' (issued at) claim.
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

    header = {
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": agent.did
    }

    # Base64URL Encode Header & Payload
    b64_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
    b64_payload = base64.urlsafe_b64encode(json.dumps(payload_copy).encode()).rstrip(b'=')

    # Create Signing Input
    signing_input = b64_header + b'.' + b64_payload

    # Sign
    signature = agent.sign(signing_input)
    b64_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')

    return (signing_input + b'.' + b64_signature).decode('utf-8')

def verify_jws(token: str) -> dict:
    """
    Verifies a JWS. Returns the payload if valid, raises error if not.

    Args:
        token: The compact JWS token string to verify

    Returns:
        The verified payload as a dictionary

    Raises:
        Exception: If signature is invalid or token is expired
    """
    try:
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
        signer_did = header.get('kid')

        # 2. Resolve the DID to a Public Key
        verify_key = resolve_did_to_key(signer_did)

        # 3. Verify Signature
        signing_input = (header_segment + "." + payload_segment).encode()
        signature = _b64url_decode(crypto_segment)

        verify_key.verify(signing_input, signature)

        # 4. Decode Payload
        payload_data = _b64url_decode(payload_segment)
        payload = json.loads(payload_data)

        # 5. Check Expiration (if present)
        if 'exp' in payload:
            current_time = int(time.time())
            exp_time = payload['exp']

            if current_time >= exp_time:
                # Calculate how long ago it expired for better error message
                expired_seconds = current_time - exp_time
                raise Exception(f"Token expired {expired_seconds} seconds ago")

        # 6. Return Payload
        return payload

    except BadSignatureError as e:
        raise Exception(f"Verification Failed: Invalid signature - {str(e)}")
    except ValueError as e:
        raise Exception(f"Verification Failed: Malformed token - {str(e)}")
    except Exception as e:
        # Re-raise our custom exceptions (like expiration) as-is
        if "Token expired" in str(e) or "Verification Failed" in str(e):
            raise
        # Wrap unexpected exceptions
        raise Exception(f"Verification Failed: {str(e)}")
