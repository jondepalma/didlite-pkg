#!/usr/bin/env python3
"""
Manual Test Scenario 4: JWK Export to Authlib

This script demonstrates:
- Creating a didlite identity
- Exporting public key as JWK
- Importing JWK into authlib
- Verifying didlite token with authlib

Note: Requires authlib to be installed (pip install authlib)
"""

try:
    from authlib.jose import JsonWebSignature, JsonWebKey
except ImportError:
    print("=" * 60)
    print("ERROR: authlib is required for this test")
    print("=" * 60)
    print("\nInstall with: pip install authlib")
    print("Or install test dependencies: pip install -e '.[test]'")
    exit(1)

from didlite.core import AgentIdentity
from didlite.jws import create_jws

print("=" * 60)
print("Scenario 4: JWK Export to Authlib")
print("=" * 60)

# Create didlite identity
print("\n1. Creating didlite identity...")
agent = AgentIdentity()
print(f"   DID: {agent.did}")

# Create a token with didlite
print("\n2. Creating token with didlite...")
payload = {"source": "didlite", "destination": "authlib"}
token = create_jws(agent, payload)
print(f"   Token: {token[:50]}...")

# Export public key to authlib
print("\n3. Exporting public key as JWK...")
jwk_dict = agent.to_jwk(include_private=False)
print(f"   JWK: {jwk_dict}")

print("\n4. Importing JWK into authlib...")
authlib_key = JsonWebKey.import_key(jwk_dict)
print(f"   Authlib key type: {type(authlib_key)}")

# Verify didlite token with authlib
print("\n5. Verifying didlite token with authlib...")
jws = JsonWebSignature()
verified_data = jws.deserialize_compact(token, authlib_key)
print(f"   ✓ Authlib verified didlite token!")
print(f"   Header: {verified_data['header']}")
print(f"   Payload: {verified_data['payload']}")

# Verify payload matches (note: includes auto-added 'iat' timestamp)
print("\n6. Validation:")
import json
payload_bytes = verified_data['payload']
payload_decoded = json.loads(payload_bytes.decode('utf-8'))
assert payload_decoded["source"] == payload["source"], "Source mismatch!"
assert payload_decoded["destination"] == payload["destination"], "Destination mismatch!"
assert "iat" in payload_decoded, "Missing 'iat' timestamp!"
print("   ✓ Payload integrity confirmed!")
print("   ✓ Cross-library interoperability verified!")
print(f"   ✓ Token issued at: {payload_decoded['iat']} (Unix timestamp)")

print("\n" + "=" * 60)
print("Scenario 4: PASSED")
print("=" * 60)
