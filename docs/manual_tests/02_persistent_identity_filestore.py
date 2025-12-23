#!/usr/bin/env python3
"""
Manual Test Scenario 2: Persistent Identity with FileKeyStore

This script demonstrates:
- Creating encrypted file storage
- Creating a persistent identity
- Simulating an application restart
- Verifying identity persistence across sessions
"""

import tempfile
import shutil
from didlite.core import AgentIdentity
from didlite.keystore import FileKeyStore

print("=" * 60)
print("Scenario 2: Persistent Identity with FileKeyStore")
print("=" * 60)

# Create a temporary directory for testing
test_dir = tempfile.mkdtemp(prefix="didlite_test_")
print(f"\n1. Created test directory: {test_dir}")

try:
    # Create encrypted file storage
    print("\n2. Creating encrypted file storage...")
    store = FileKeyStore(test_dir, password="test_password_123")
    print("   ✓ FileKeyStore initialized")

    # Create persistent identity (first session)
    print("\n3. First session - Creating persistent identity...")
    agent1 = AgentIdentity(keystore=store, identifier="device_001")
    did1 = agent1.did
    print(f"   First session DID: {did1}")

    # Simulate restart - load existing identity (second session)
    print("\n4. Second session - Loading existing identity...")
    agent2 = AgentIdentity(keystore=store, identifier="device_001")
    did2 = agent2.did
    print(f"   Second session DID: {did2}")

    # Verify same identity
    print("\n5. Validation:")
    assert did1 == did2, "DIDs don't match across sessions!"
    print("   ✓ Identity persisted across sessions!")
    print(f"   ✓ DID match confirmed: {did1 == did2}")

    # Verify signatures are compatible
    print("\n6. Cross-session signature verification...")
    from didlite.jws import create_jws, verify_jws

    token_session1 = create_jws(agent1, {"session": 1})
    token_session2 = create_jws(agent2, {"session": 2})

    verified1 = verify_jws(token_session1)
    verified2 = verify_jws(token_session2)

    print(f"   Session 1 token verified: {verified1}")
    print(f"   Session 2 token verified: {verified2}")
    print("   ✓ Both sessions can create and verify tokens!")

finally:
    # Clean up
    print(f"\n7. Cleaning up test directory: {test_dir}")
    shutil.rmtree(test_dir)
    print("   ✓ Cleanup complete")

print("\n" + "=" * 60)
print("Scenario 2: PASSED")
print("=" * 60)
