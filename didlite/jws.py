import time
import json
import base64
from .core import AgentIdentity, resolve_did_to_key
from nacl.exceptions import BadSignatureError

def create_jws(agent: AgentIdentity, payload: dict) -> str:
    """
    Creates a compact JWS (JSON Web Signature).
    Similar to a JWT but signed with Ed25519.
    """
    header = {
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": agent.did
    }
    
    # Base64URL Encode Header & Payload
    b64_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
    b64_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
    
    # Create Signing Input
    signing_input = b64_header + b'.' + b64_payload
    
    # Sign
    signature = agent.sign(signing_input)
    b64_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')
    
    return (signing_input + b'.' + b64_signature).decode('utf-8')

def verify_jws(token: str) -> dict:
    """
    Verifies a JWS. Returns the payload if valid, raises error if not.
    """
    try:
        header_segment, payload_segment, crypto_segment = token.split('.')
        
        # 1. Decode Header to find the 'kid' (Key ID / DID)
        header_data = base64.urlsafe_b64decode(header_segment + "==")
        header = json.loads(header_data)
        signer_did = header.get('kid')
        
        # 2. Resolve the DID to a Public Key
        verify_key = resolve_did_to_key(signer_did)
        
        # 3. Verify Signature
        signing_input = (header_segment + "." + payload_segment).encode()
        signature = base64.urlsafe_b64decode(crypto_segment + "==")
        
        verify_key.verify(signing_input, signature)
        
        # 4. Return Payload
        payload_data = base64.urlsafe_b64decode(payload_segment + "==")
        return json.loads(payload_data)
        
    except (ValueError, BadSignatureError) as e:
        raise Exception(f"Verification Failed: {str(e)}")
