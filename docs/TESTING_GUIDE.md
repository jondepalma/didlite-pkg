# didlite Testing Guide

This guide explains how to run tests, understand test coverage, and verify the functionality of the didlite library.

## Quick Start

### Install Test Dependencies

```bash
# Install package with test extras
pip install -e ".[test]"
```

### Run All Tests

```bash
# Run the full test suite
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=didlite --cov-report=term-missing
```

### Quick Verification Script

For a quick end-to-end verification without pytest:

```bash
python docs/verify_test.py
```

Expected output: Generates a new DID and signed JWS token with verification.

## Test Suite Overview

The test suite contains **101 tests** organized into 4 categories:

| Category | Tests | Description |
|----------|-------|-------------|
| Core (`test_core.py`) | 30 | Identity generation, DID resolution, JWK/PEM export/import, security validation |
| JWS (`test_jws.py`) | 34 | Token creation, verification, TTL expiration |
| Keystore (`test_keystore.py`) | 32 | All storage backends (Memory, Env, File), corruption detection |
| Integration (`test_integration.py`) | 5 | Authlib interoperability |

## Running Specific Test Categories

### Core Identity Tests

Tests for `AgentIdentity` class and `did:key` resolution:

```bash
# Run all core tests
pytest tests/test_core.py -v

# Run specific test class
pytest tests/test_core.py::TestAgentIdentity -v

# Run specific test
pytest tests/test_core.py::TestAgentIdentity::test_jwk_roundtrip_signature_verification -v
```

**What's tested:**
- Random identity generation
- Deterministic identity from seed
- DID format compliance (`did:key:z...`)
- Ed25519 signature creation and verification
- JWK export/import (RFC 7517)
  - Invalid JWK private key size validation
- PEM export/import (PKCS8 and SubjectPublicKeyInfo)
  - Non-Ed25519 key type rejection (RSA, ECDSA)
- Cross-format consistency (JWK ↔ PEM)

### JWS Token Tests

Tests for JWT/JWS token creation and verification:

```bash
# Run all JWS tests
pytest tests/test_jws.py -v

# Run specific test category
pytest tests/test_jws.py::TestJWSTTLExpiration -v
```

**What's tested:**
- Token creation with EdDSA signing
- Compact JWS format (RFC 7515)
- Token verification and payload extraction
- Tamper detection (modified payload/signature)
- TTL expiration with `iat` and `exp` claims
- Edge cases (zero TTL, negative expiration, clock boundaries)
- Backward compatibility (tokens without expiration)

### Keystore Tests

Tests for persistent identity storage:

```bash
# Run all keystore tests
pytest tests/test_keystore.py -v

# Run specific backend tests
pytest tests/test_keystore.py::TestFileKeyStore -v
pytest tests/test_keystore.py::TestMemoryKeyStore -v
pytest tests/test_keystore.py::TestEnvKeyStore -v
```

**What's tested:**
- **MemoryKeyStore**: In-memory storage (ephemeral)
- **EnvKeyStore**: Environment variable storage
  - Corrupted seed size detection
  - Invalid base64 encoding handling
- **FileKeyStore**: Encrypted file storage (PBKDF2 + Fernet)
  - Corrupted encrypted file detection
- AgentIdentity integration (persistence across restarts)
- Security: file permissions (0o600), path traversal protection
- Error handling: wrong passwords, invalid seeds, data corruption

### Integration Tests

Tests for interoperability with authlib:

```bash
# Run integration tests
pytest tests/test_integration.py -v
```

**What's tested:**
- Bidirectional token verification (didlite ↔ authlib)
- JWK export to authlib, import from authlib
- Roundtrip consistency
- Standards compliance (RFC 7515, RFC 7517)

## Coverage Reporting

### Generate Coverage Report

```bash
# Terminal report with missing lines
pytest --cov=didlite --cov-report=term-missing

# HTML report (opens in browser)
pytest --cov=didlite --cov-report=html
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

### Current Coverage

The test suite provides excellent coverage across all modules:

| Module | Coverage | Details |
|--------|----------|---------|
| `didlite/__init__.py` | 100% | Complete coverage |
| `didlite/core.py` | 100% | Complete coverage ✨ |
| `didlite/jws.py` | 98% | 1 defensive exception handler uncovered |
| `didlite/keystore.py` | 95% | 5 acceptable gaps (see policy below) |
| **Overall** | **98%** | **6 uncovered lines (all acceptable)** |

### Coverage Policy

**Target:** ≥ 95% coverage

**Acceptable gaps** (lines that don't require testing):

1. **Abstract method placeholders** - `pass` statements in ABC base classes
   - Example: `keystore.py:33, 49, 62`
   - Rationale: These should never execute; all concrete implementations are fully tested

2. **Defensive exception handlers** - Generic wrappers for truly unexpected errors
   - Example: `jws.py:127`
   - Rationale: Main error paths are comprehensively tested; these catch edge cases

3. **Trivial edge cases** - Simple operations already tested in similar contexts
   - Example: `keystore.py:142, 263` (delete non-existent seed returns False)
   - Rationale: Minimal business logic value; pattern tested in other implementations

**Why 98% is excellent:**
- Security-critical code paths: 100% covered
- Cryptographic operations: 100% covered
- Data integrity checks: 100% covered
- All keystore implementations: Fully tested
- Remaining gaps are defensive/abstract code with minimal security impact

## Manual Testing Scenarios

### Scenario 1: Basic Identity and Token Creation

```python
from didlite.core import AgentIdentity
from didlite.jws import create_jws, verify_jws

# Create a new identity
agent = AgentIdentity()
print(f"DID: {agent.did}")

# Create a signed token
payload = {"message": "Hello, World!", "user_id": 123}
token = create_jws(agent, payload)
print(f"Token: {token[:50]}...")

# Verify the token
verified = verify_jws(token)
print(f"Verified payload: {verified}")
```

### Scenario 2: Persistent Identity with FileKeyStore

```python
from didlite.core import AgentIdentity
from didlite.keystore import FileKeyStore

# Create encrypted file storage
store = FileKeyStore("/tmp/didlite-keys", password="test_password_123")

# Create persistent identity
agent1 = AgentIdentity(keystore=store, identifier="device_001")
did1 = agent1.did
print(f"First session DID: {did1}")

# Simulate restart - load existing identity
agent2 = AgentIdentity(keystore=store, identifier="device_001")
did2 = agent2.did
print(f"Second session DID: {did2}")

# Verify same identity
assert did1 == did2
print("✓ Identity persisted across sessions!")
```

### Scenario 3: Token Expiration

```python
from didlite.core import AgentIdentity
from didlite.jws import create_jws, verify_jws
import time

agent = AgentIdentity()

# Create token with 2-second expiration
payload = {"data": "temporary"}
token = create_jws(agent, payload, expires_in=2)

# Immediate verification succeeds
verified = verify_jws(token)
print(f"Immediate verification: {verified}")

# Wait for expiration
time.sleep(3)

# Verification fails
try:
    verify_jws(token)
except ValueError as e:
    print(f"✓ Token expired: {e}")
```

### Scenario 4: JWK Export to Authlib

```python
from didlite.core import AgentIdentity
from didlite.jws import create_jws
from authlib.jose import JsonWebSignature, JsonWebKey

# Create didlite identity
agent = AgentIdentity()
payload = {"source": "didlite", "destination": "authlib"}
token = create_jws(agent, payload)

# Export public key to authlib
jwk_dict = agent.to_jwk(include_private=False)
authlib_key = JsonWebKey.import_key(jwk_dict)

# Verify didlite token with authlib
jws = JsonWebSignature()
verified_data = jws.deserialize_compact(token, authlib_key)
print(f"✓ Authlib verified didlite token: {verified_data['payload']}")
```

### Scenario 5: PEM Export for OpenSSL

```python
from didlite.core import AgentIdentity

agent = AgentIdentity()

# Export private key to PEM (PKCS8 format)
private_pem = agent.to_pem(include_private=True)
print("Private Key PEM:")
print(private_pem)

# Export public key to PEM (SubjectPublicKeyInfo format)
public_pem = agent.to_pem(include_private=False)
print("\nPublic Key PEM:")
print(public_pem)

# Can be saved to files for use with OpenSSL
with open("/tmp/private.pem", "w") as f:
    f.write(private_pem)
with open("/tmp/public.pem", "w") as f:
    f.write(public_pem)
```

## Continuous Integration

### Running Tests in CI

```yaml
# Example GitHub Actions workflow
- name: Run tests
  run: |
    pip install -e ".[test]"
    pytest --cov=didlite --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v3
```

### Pre-commit Testing

```bash
# Run before committing changes
pytest -v && echo "✓ All tests passed!"
```

## Troubleshooting

### ImportError: No module named 'didlite'

**Solution**: Install in editable mode:
```bash
pip install -e .
```

### ImportError: No module named 'authlib'

**Solution**: Install test dependencies:
```bash
pip install -e ".[test]"
```

### FileKeyStore permission errors

**Solution**: Ensure the storage directory is writable:
```bash
chmod 700 /path/to/keystore/dir
```

### Tests fail with "seed must be 32 bytes"

**Cause**: Incorrect seed length when creating deterministic identities.

**Solution**: Ensure seeds are exactly 32 bytes:
```python
seed = b"my_secret" + b"\x00" * 23  # Pad to 32 bytes
agent = AgentIdentity(seed=seed)
```

## Test Development Guidelines

### Adding New Tests

1. **Choose the right test file:**
   - `test_core.py`: Identity and DID functionality
   - `test_jws.py`: Token creation and verification
   - `test_keystore.py`: Storage backends
   - `test_integration.py`: Third-party library integration

2. **Follow naming conventions:**
   - Test classes: `TestFeatureName`
   - Test methods: `test_specific_behavior`

3. **Use descriptive docstrings:**
   ```python
   def test_expired_token_fails_verification(self):
       """Test that tokens past their expiration time fail verification"""
   ```

4. **Test edge cases:**
   - Invalid inputs
   - Boundary conditions
   - Error paths

5. **Keep tests isolated:**
   - Use `setup_method()` for test fixtures
   - Clean up temp files in `teardown_method()`

### Running Tests During Development

```bash
# Run specific test during development
pytest tests/test_core.py::TestAgentIdentity::test_jwk_export -v

# Run with automatic re-run on file changes (requires pytest-watch)
pip install pytest-watch
ptw -- tests/test_core.py
```

## Performance Testing

### Benchmark Identity Generation

```python
import time
from didlite.core import AgentIdentity

start = time.time()
for i in range(100):
    agent = AgentIdentity()
elapsed = time.time() - start
print(f"Generated 100 identities in {elapsed:.2f}s ({elapsed*10:.2f}ms each)")
```

### Benchmark Token Creation

```python
import time
from didlite.core import AgentIdentity
from didlite.jws import create_jws

agent = AgentIdentity()
payload = {"test": "data", "count": 123}

start = time.time()
for i in range(100):
    token = create_jws(agent, payload)
elapsed = time.time() - start
print(f"Created 100 tokens in {elapsed:.2f}s ({elapsed*10:.2f}ms each)")
```

## Summary

- **101 tests** covering all functionality
- **4 test categories**: Core, JWS, Keystore, Integration
- **Excellent coverage**: 98% overall, with 100% on security-critical code
- **Fast execution**: Full suite runs in ~7.7 seconds
- **No skipped tests**: All tests are active and passing

### Test Coverage Statistics

```
Total Statements: 251
Covered: 245
Missing: 6 (all acceptable per coverage policy)
Coverage: 98%
```

### Coverage by Priority

- **Security-critical code**: 100% (cryptographic operations, key validation)
- **Data integrity**: 100% (corruption detection, validation)
- **Business logic**: 98%+ (all core functionality)
- **Defensive code**: Partially covered (acceptable gaps documented)

For questions or issues with testing, refer to the main README.md or open an issue on Gitea.
