#!/usr/bin/env python3
"""
Manual Test Scenario 5: PEM Export for OpenSSL

This script demonstrates:
- Exporting private key to PEM (PKCS8 format)
- Exporting public key to PEM (SubjectPublicKeyInfo format)
- Saving PEM files to disk
- Verifying PEM format structure
"""

import tempfile
import os
from didlite.core import AgentIdentity

print("=" * 60)
print("Scenario 5: PEM Export for OpenSSL")
print("=" * 60)

print("\n1. Creating identity...")
agent = AgentIdentity()
print(f"   DID: {agent.did}")

# Export private key to PEM (PKCS8 format)
print("\n2. Exporting private key to PEM (PKCS8 format)...")
private_pem = agent.to_pem(include_private=True)
print("   Private Key PEM:")
print("-" * 60)
print(private_pem)
print("-" * 60)

# Export public key to PEM (SubjectPublicKeyInfo format)
print("\n3. Exporting public key to PEM (SubjectPublicKeyInfo format)...")
public_pem = agent.to_pem(include_private=False)
print("   Public Key PEM:")
print("-" * 60)
print(public_pem)
print("-" * 60)

# Validate PEM format
print("\n4. Validating PEM format...")
assert private_pem.startswith("-----BEGIN PRIVATE KEY-----"), "Invalid private PEM header"
assert private_pem.endswith("-----END PRIVATE KEY-----\n"), "Invalid private PEM footer"
assert public_pem.startswith("-----BEGIN PUBLIC KEY-----"), "Invalid public PEM header"
assert public_pem.endswith("-----END PUBLIC KEY-----\n"), "Invalid public PEM footer"
print("   ✓ PEM format validation passed!")

# Save to temporary files
print("\n5. Saving PEM files to temporary directory...")
temp_dir = tempfile.mkdtemp(prefix="didlite_pem_")
private_path = os.path.join(temp_dir, "private.pem")
public_path = os.path.join(temp_dir, "public.pem")

with open(private_path, "w") as f:
    f.write(private_pem)
print(f"   Private key saved to: {private_path}")

with open(public_path, "w") as f:
    f.write(public_pem)
print(f"   Public key saved to: {public_path}")

# Verify file permissions (should be readable)
print("\n6. Verifying file permissions...")
private_stat = os.stat(private_path)
public_stat = os.stat(public_path)
print(f"   Private key permissions: {oct(private_stat.st_mode)[-3:]}")
print(f"   Public key permissions: {oct(public_stat.st_mode)[-3:]}")

# Test PEM import roundtrip
print("\n7. Testing PEM import roundtrip...")
agent2 = AgentIdentity.from_pem(private_pem)
print(f"   Original DID: {agent.did}")
print(f"   Imported DID: {agent2.did}")
assert agent.did == agent2.did, "DID mismatch after PEM roundtrip!"
print("   ✓ PEM roundtrip successful!")

# Cleanup
print(f"\n8. Cleaning up temporary files...")
os.remove(private_path)
os.remove(public_path)
os.rmdir(temp_dir)
print("   ✓ Cleanup complete")

print("\n" + "=" * 60)
print("Scenario 5: PASSED")
print("=" * 60)
print(f"\nNote: PEM files can be used with OpenSSL tools")
print(f"Example: openssl pkey -in private.pem -text -noout")
