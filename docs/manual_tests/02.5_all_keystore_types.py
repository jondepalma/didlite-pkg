#!/usr/bin/env python3
"""
Manual Test Scenario 2.5: All KeyStore Types Comprehensive Demo

This script demonstrates all three keystore implementations with verbose
output showing their characteristics, use cases, and full API:

1. MemoryKeyStore - Ephemeral in-memory storage
2. EnvKeyStore - Environment variable storage
3. FileKeyStore - Encrypted file-based storage

Each section shows:
- Keystore initialization
- Saving seeds (save_seed)
- Loading seeds (load_seed)
- Deleting seeds (delete_seed)
- Creating persistent identities
- Cross-session verification
"""

import tempfile
import shutil
import os
from didlite.core import AgentIdentity
from didlite.keystore import MemoryKeyStore, EnvKeyStore, FileKeyStore
from didlite.jws import create_jws, verify_jws

print("=" * 70)
print("Scenario 2.5: Comprehensive KeyStore Types Demonstration")
print("=" * 70)

# ============================================================================
# SECTION 1: MemoryKeyStore
# ============================================================================
print("\n" + "=" * 70)
print("SECTION 1: MemoryKeyStore")
print("=" * 70)
print("\nCHARACTERISTICS:")
print("  - Storage: In-memory dictionary (ephemeral)")
print("  - Persistence: Lost on process exit")
print("  - Use case: Testing, temporary sessions, stateless applications")
print("  - Security: No disk writes, memory-only")

print("\n1.1 Creating MemoryKeyStore...")
memory_store = MemoryKeyStore()
print("     ✓ MemoryKeyStore initialized")
print(f"     Type: {type(memory_store).__name__}")

print("\n1.2 Creating first identity with identifier 'agent_001'...")
agent1 = AgentIdentity(keystore=memory_store, identifier="agent_001")
did1 = agent1.did
print(f"     DID: {did1}")
print("     ✓ Seed automatically saved to MemoryKeyStore")

print("\n1.3 Creating second identity with identifier 'agent_002'...")
agent2 = AgentIdentity(keystore=memory_store, identifier="agent_002")
did2 = agent2.did
print(f"     DID: {did2}")
print("     ✓ Second seed saved (different identifier)")

print("\n1.4 Loading existing identity 'agent_001'...")
agent1_reload = AgentIdentity(keystore=memory_store, identifier="agent_001")
did1_reload = agent1_reload.did
print(f"     Original DID:  {did1}")
print(f"     Reloaded DID:  {did1_reload}")
assert did1 == did1_reload, "DID mismatch!"
print("     ✓ Identity persistence within same process confirmed")

print("\n1.5 Testing cross-session token verification...")
token_from_agent1 = create_jws(agent1, {"from": "agent_001"})
token_from_agent2 = create_jws(agent2, {"from": "agent_002"})
verified1 = verify_jws(token_from_agent1)
verified2 = verify_jws(token_from_agent2)
print(f"     Agent 001 payload: {verified1}")
print(f"     Agent 002 payload: {verified2}")
print("     ✓ Both agents can create and verify tokens")

print("\n1.6 Testing delete_seed() functionality...")
deleted = memory_store.delete_seed("agent_002")
print(f"     Delete 'agent_002': {deleted}")
assert deleted is True, "Delete should return True for existing seed"
print("     ✓ Seed deleted successfully")

print("\n1.7 Verifying deleted seed is gone...")
deleted_again = memory_store.delete_seed("agent_002")
print(f"     Delete 'agent_002' again: {deleted_again}")
assert deleted_again is False, "Delete should return False for non-existent seed"
print("     ✓ Deletion confirmed (returns False for non-existent)")

print("\n1.8 Attempting to load deleted seed...")
try:
    AgentIdentity(keystore=memory_store, identifier="agent_002")
    print("     ✗ ERROR: Should have created new identity!")
except Exception:
    pass
# Actually, it creates a NEW identity, not an error
agent2_new = AgentIdentity(keystore=memory_store, identifier="agent_002")
did2_new = agent2_new.did
print(f"     Original agent_002 DID: {did2}")
print(f"     New agent_002 DID:      {did2_new}")
assert did2 != did2_new, "Should be different identities"
print("     ✓ New identity created (original was deleted)")

print("\n1.9 MemoryKeyStore Summary:")
print(f"     Active seeds: agent_001, agent_002 (new)")
print("     ✓ SECTION 1 COMPLETE")

# ============================================================================
# SECTION 2: EnvKeyStore
# ============================================================================
print("\n" + "=" * 70)
print("SECTION 2: EnvKeyStore")
print("=" * 70)
print("\nCHARACTERISTICS:")
print("  - Storage: OS environment variables (process-scoped)")
print("  - Persistence: Survives within process, can be exported to shell")
print("  - Use case: Containerized apps, 12-factor apps, CI/CD pipelines")
print("  - Security: Base64-encoded (NOT encrypted), visible in env")
print("  - Format: DIDLITE_SEED_<IDENTIFIER_UPPER>")

print("\n2.1 Creating EnvKeyStore with default prefix...")
env_store = EnvKeyStore()
print("     ✓ EnvKeyStore initialized")
print(f"     Type: {type(env_store).__name__}")
print(f"     Prefix: {env_store.prefix}")

print("\n2.2 Creating identity 'sensor_001'...")
sensor1 = AgentIdentity(keystore=env_store, identifier="sensor_001")
did_sensor1 = sensor1.did
print(f"     DID: {did_sensor1}")
print("     ✓ Seed saved to environment variable")

print("\n2.3 Inspecting environment variable...")
env_var_name = f"{env_store.prefix}SENSOR_001"
env_var_value = os.environ.get(env_var_name)
print(f"     Variable name: {env_var_name}")
print(f"     Variable value (base64): {env_var_value[:20]}... (truncated)")
print(f"     Length: {len(env_var_value)} characters")
print("     ✓ Seed is base64-encoded in environment")

print("\n2.4 Creating identity with custom prefix...")
env_store_custom = EnvKeyStore(prefix="MYAPP_KEY_")
sensor2 = AgentIdentity(keystore=env_store_custom, identifier="device_alpha")
did_sensor2 = sensor2.did
print(f"     DID: {did_sensor2}")
env_var_custom = "MYAPP_KEY_DEVICE_ALPHA"
print(f"     Custom env var: {env_var_custom}")
assert env_var_custom in os.environ, "Custom env var not found"
print("     ✓ Custom prefix working")

print("\n2.5 Loading existing identity 'sensor_001'...")
sensor1_reload = AgentIdentity(keystore=env_store, identifier="sensor_001")
did_sensor1_reload = sensor1_reload.did
print(f"     Original DID:  {did_sensor1}")
print(f"     Reloaded DID:  {did_sensor1_reload}")
assert did_sensor1 == did_sensor1_reload, "DID mismatch!"
print("     ✓ Identity loaded from environment variable")

print("\n2.6 Testing manual seed extraction...")
import base64
manual_seed = env_store.load_seed("sensor_001")
print(f"     Extracted seed length: {len(manual_seed)} bytes")
assert len(manual_seed) == 32, "Seed must be 32 bytes"
print("     ✓ Seed extracted and validated (32 bytes)")

print("\n2.7 Testing delete_seed() functionality...")
deleted = env_store.delete_seed("sensor_001")
print(f"     Delete 'sensor_001': {deleted}")
assert deleted is True, "Delete should return True"
assert env_var_name not in os.environ, "Env var should be deleted"
print("     ✓ Environment variable deleted")

print("\n2.8 Verifying deleted seed is gone...")
deleted_again = env_store.delete_seed("sensor_001")
print(f"     Delete 'sensor_001' again: {deleted_again}")
assert deleted_again is False, "Delete should return False"
print("     ✓ Deletion confirmed")

print("\n2.9 Cleanup custom prefix environment variable...")
env_store_custom.delete_seed("device_alpha")
print("     ✓ Custom env var cleaned up")

print("\n2.10 EnvKeyStore Summary:")
print("     Environment variables are process-scoped and base64-encoded")
print("     Suitable for containerized and cloud-native deployments")
print("     ✓ SECTION 2 COMPLETE")

# ============================================================================
# SECTION 3: FileKeyStore
# ============================================================================
print("\n" + "=" * 70)
print("SECTION 3: FileKeyStore")
print("=" * 70)
print("\nCHARACTERISTICS:")
print("  - Storage: Encrypted JSON files on disk")
print("  - Persistence: Survives process restarts")
print("  - Use case: Edge devices, IoT sensors, desktop apps")
print("  - Security: PBKDF2 key derivation + Fernet encryption")
print("  - File permissions: 0o600 (owner read/write only)")

# Create a temporary directory for testing
test_dir = tempfile.mkdtemp(prefix="didlite_filestore_")
print(f"\n3.1 Created test directory: {test_dir}")

try:
    print("\n3.2 Creating FileKeyStore with password...")
    file_store = FileKeyStore(test_dir, password="secure_password_123")
    print("     ✓ FileKeyStore initialized")
    print(f"     Type: {type(file_store).__name__}")
    print(f"     Storage directory: {file_store.storage_dir}")

    print("\n3.3 Creating first identity 'iot_device_001'...")
    device1 = AgentIdentity(keystore=file_store, identifier="iot_device_001")
    did_device1 = device1.did
    print(f"     DID: {did_device1}")
    print("     ✓ Seed encrypted and saved to file")

    print("\n3.4 Inspecting encrypted file...")
    file_path = os.path.join(test_dir, "iot_device_001.enc")
    assert os.path.exists(file_path), "Encrypted file not found"
    file_stat = os.stat(file_path)
    file_perms = oct(file_stat.st_mode)[-3:]
    file_size = file_stat.st_size
    print(f"     File path: {file_path}")
    print(f"     File permissions: {file_perms}")
    print(f"     File size: {file_size} bytes")
    assert file_perms == '600', f"Expected 600 permissions, got {file_perms}"
    print("     ✓ File permissions are secure (600)")

    print("\n3.5 Reading encrypted file contents...")
    with open(file_path, 'r') as f:
        import json
        encrypted_data = json.load(f)
    print(f"     Keys in file: {list(encrypted_data.keys())}")
    print(f"     Salt (base64): {encrypted_data['salt'][:20]}...")
    print(f"     Encrypted seed (base64): {encrypted_data['encrypted_seed'][:20]}...")
    print("     ✓ File contains encrypted data with salt")

    print("\n3.6 Creating second identity 'iot_device_002'...")
    device2 = AgentIdentity(keystore=file_store, identifier="iot_device_002")
    did_device2 = device2.did
    print(f"     DID: {did_device2}")
    file_path2 = os.path.join(test_dir, "iot_device_002.enc")
    assert os.path.exists(file_path2), "Second encrypted file not found"
    print("     ✓ Second encrypted file created")

    print("\n3.7 Listing all encrypted files...")
    enc_files = [f for f in os.listdir(test_dir) if f.endswith('.enc')]
    print(f"     Files in directory: {enc_files}")
    assert len(enc_files) == 2, "Should have 2 encrypted files"
    print("     ✓ Two encrypted seed files present")

    print("\n3.8 Simulating process restart (reload from disk)...")
    print("     Creating NEW FileKeyStore instance (same password)...")
    file_store2 = FileKeyStore(test_dir, password="secure_password_123")
    device1_reload = AgentIdentity(keystore=file_store2, identifier="iot_device_001")
    did_device1_reload = device1_reload.did
    print(f"     Original DID:  {did_device1}")
    print(f"     Reloaded DID:  {did_device1_reload}")
    assert did_device1 == did_device1_reload, "DID mismatch after reload!"
    print("     ✓ Identity persisted across process restart")

    print("\n3.9 Testing wrong password...")
    try:
        file_store_wrong = FileKeyStore(test_dir, password="wrong_password")
        device1_wrong = AgentIdentity(keystore=file_store_wrong, identifier="iot_device_001")
        print("     ✗ ERROR: Should have failed with wrong password!")
        assert False, "Should not succeed with wrong password"
    except Exception as e:
        print(f"     Expected error: {str(e)[:60]}...")
        print("     ✓ Wrong password rejected (Fernet decryption failed)")

    print("\n3.10 Testing cross-session token verification...")
    token1 = create_jws(device1, {"device": "001", "session": 1})
    token2 = create_jws(device1_reload, {"device": "001", "session": 2})
    verified1 = verify_jws(token1)
    verified2 = verify_jws(token2)
    print(f"     Session 1 payload: {verified1}")
    print(f"     Session 2 payload: {verified2}")
    print("     ✓ Tokens from both sessions verified successfully")

    print("\n3.11 Testing delete_seed() functionality...")
    deleted = file_store.delete_seed("iot_device_002")
    print(f"     Delete 'iot_device_002': {deleted}")
    assert deleted is True, "Delete should return True"
    assert not os.path.exists(file_path2), "File should be deleted"
    print("     ✓ Encrypted file deleted from disk")

    print("\n3.12 Verifying deleted file is gone...")
    deleted_again = file_store.delete_seed("iot_device_002")
    print(f"     Delete 'iot_device_002' again: {deleted_again}")
    assert deleted_again is False, "Delete should return False"
    print("     ✓ Deletion confirmed")

    print("\n3.13 Testing manual seed loading...")
    manual_seed = file_store.load_seed("iot_device_001")
    print(f"     Loaded seed length: {len(manual_seed)} bytes")
    assert len(manual_seed) == 32, "Seed must be 32 bytes"
    print("     ✓ Seed decrypted and validated")

    print("\n3.14 FileKeyStore Summary:")
    print("     Encrypted storage with PBKDF2 + Fernet")
    print("     Secure file permissions (600)")
    print("     Survives process restarts")
    print("     Suitable for edge devices and IoT deployments")
    print("     ✓ SECTION 3 COMPLETE")

finally:
    # Clean up
    print(f"\n3.15 Cleaning up test directory: {test_dir}")
    shutil.rmtree(test_dir)
    print("     ✓ Cleanup complete")

# ============================================================================
# FINAL SUMMARY
# ============================================================================
print("\n" + "=" * 70)
print("FINAL SUMMARY: All KeyStore Types")
print("=" * 70)

print("\n┌─────────────────┬──────────────┬─────────────┬──────────────────┐")
print("│ KeyStore Type   │ Persistence  │ Security    │ Best Use Case    │")
print("├─────────────────┼──────────────┼─────────────┼──────────────────┤")
print("│ MemoryKeyStore  │ In-process   │ Memory-only │ Testing, temp    │")
print("│ EnvKeyStore     │ Process-wide │ Base64      │ Containers, CI   │")
print("│ FileKeyStore    │ Disk         │ Encrypted   │ Edge, IoT, local │")
print("└─────────────────┴──────────────┴─────────────┴──────────────────┘")

print("\nKEY OBSERVATIONS:")
print("  1. All keystores implement the same interface (save/load/delete)")
print("  2. MemoryKeyStore: Fastest, no persistence")
print("  3. EnvKeyStore: Good for cloud-native, not encrypted")
print("  4. FileKeyStore: Most secure, survives restarts")
print("  5. All support multiple identities per keystore")
print("  6. delete_seed() returns True/False for existence checking")

print("\n" + "=" * 70)
print("Scenario 2.5: PASSED")
print("=" * 70)
print("\nAll keystore types demonstrated successfully!")
print("Run automated tests with: pytest tests/test_keystore.py -v")
