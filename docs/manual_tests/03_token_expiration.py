#!/usr/bin/env python3
"""
Manual Test Scenario 3: Token Expiration

This script demonstrates:
- Creating a token with TTL (time-to-live)
- Immediate verification (should succeed)
- Verification after expiration (should fail)
"""

import time
from didlite.core import AgentIdentity
from didlite.jws import create_jws, verify_jws

print("=" * 60)
print("Scenario 3: Token Expiration")
print("=" * 60)

print("\n1. Creating identity...")
agent = AgentIdentity()
print(f"   DID: {agent.did}")

# Create token with 2-second expiration
print("\n2. Creating token with 2-second expiration...")
payload = {"data": "temporary"}
token = create_jws(agent, payload, expires_in=2)
print(f"   Token created: {token[:50]}...")

# Immediate verification succeeds
print("\n3. Immediate verification (should succeed)...")
verified = verify_jws(token)
print(f"   Verified payload: {verified}")
print("   ✓ Immediate verification successful!")

# Wait for expiration
print("\n4. Waiting 3 seconds for token to expire...")
for i in range(3):
    time.sleep(1)
    print(f"   {i+1}s elapsed...")

# Verification fails
print("\n5. Verification after expiration (should fail)...")
try:
    verify_jws(token)
    print("   ✗ ERROR: Token should have expired but didn't!")
    raise AssertionError("Token expiration check failed")
except Exception as e:
    if "Token expired" in str(e):
        print(f"   ✓ Token correctly expired: {e}")
    else:
        print(f"   ✗ Unexpected error: {e}")
        raise

print("\n" + "=" * 60)
print("Scenario 3: PASSED")
print("=" * 60)
