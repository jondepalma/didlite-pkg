#!/usr/bin/env python3
"""
Manual Test Scenario 1: Basic Identity and Token Creation

This script demonstrates:
- Creating a new ephemeral identity
- Generating a DID
- Creating a signed JWS token
- Verifying the token
"""

from didlite.core import AgentIdentity
from didlite.jws import create_jws, verify_jws

print("=" * 60)
print("Scenario 1: Basic Identity and Token Creation")
print("=" * 60)

# Create a new identity
print("\n1. Creating a new identity...")
agent = AgentIdentity()
print(f"   DID: {agent.did}")

# Create a signed token
print("\n2. Creating a signed token...")
payload = {"message": "Hello, World!", "user_id": 123}
token = create_jws(agent, payload)
print(f"   Token: {token[:50]}...")
print(f"   Token length: {len(token)} characters")

# Verify the token
print("\n3. Verifying the token...")
verified = verify_jws(token)
print(f"   Verified payload: {verified}")

# Confirm payload matches (note: verified includes auto-added 'iat' timestamp)
print("\n4. Validation:")
assert verified["message"] == payload["message"], "Message mismatch!"
assert verified["user_id"] == payload["user_id"], "User ID mismatch!"
assert "iat" in verified, "Missing 'iat' timestamp!"
print("   ✓ Token creation and verification successful!")
print("   ✓ Payload integrity confirmed!")
print(f"   ✓ Token issued at: {verified['iat']} (Unix timestamp)")

print("\n" + "=" * 60)
print("Scenario 1: PASSED")
print("=" * 60)
