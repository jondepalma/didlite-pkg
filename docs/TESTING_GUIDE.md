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

The test suite contains **248 tests** organized into 8 categories:

| Category | Tests | Description |
|----------|-------|-------------|
| Compliance (`test_compliance.py`) | 18 | W3C DID & RFC 7515/7519 JWT/JWS standards verification |
| Core (`test_core.py`) | 37 | Identity generation, DID resolution, JWK/PEM export/import, security validation |
| Fuzzing (`test_fuzzing.py`) | 32 | Malformed inputs, attack scenarios, DoS prevention |
| Integration (`test_integration.py`) | 5 | Authlib interoperability |
| JWS (`test_jws.py`) | 63 | Token creation, verification, TTL expiration, header validation |
| Keystore (`test_keystore.py`) | 49 | All storage backends (Memory, Env, File), corruption detection |
| OWASP Compliance (`test_owasp_compliance.py`) | 12 | OWASP Password Storage Cheat Sheet validation, PBKDF2 verification |
| Security (`test_security.py`) | 32 | Error message sanitization, input validation |

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

### OWASP Compliance Tests

Tests for OWASP Password Storage Cheat Sheet compliance:

```bash
# Run all OWASP compliance tests
pytest tests/test_owasp_compliance.py -v

# Run specific compliance test class
pytest tests/test_owasp_compliance.py::TestOWASPCompliance -v
pytest tests/test_owasp_compliance.py::TestCryptoRationaleAlignment -v
pytest tests/test_owasp_compliance.py::TestThreatModelAlignment -v
```

**What's tested:**
- **OWASP Password Storage Standards** (12 tests total)
  - PBKDF2 iteration count validation (480,000 iterations)
  - OWASP 2021 minimum compliance (310,000 iterations)
  - HMAC-SHA256 algorithm verification
  - Salt randomness and uniqueness
  - Salt length (128 bits / 16 bytes per NIST SP 800-132)
  - Output length (256 bits / 32 bytes)
- **Documentation Alignment** (`CRYPTO_RATIONALE.md`)
  - Iteration count accuracy
  - PBKDF2-HMAC-SHA256 implementation claims
  - Fernet encryption (AES-128-CBC + HMAC) verification
- **Threat Model Validation** (`THREAT_MODEL.md`)
  - Brute-force resistance calculations
  - GPU crack time estimates
  - Security margin verification

**Security Standards Validated:**
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- NIST SP 800-132 (PBKDF2 Recommendations)
- OWASP 2021 minimum: 310,000 iterations
- OWASP 2023 recommendation: 600,000 iterations

**Implementation Status:**
- Current: 480,000 iterations (55% above OWASP 2021 minimum)
- Compliance: ~80% of OWASP 2023 recommendation
- Upgrade plan: v1.0.0 will increase to 600,000 iterations with backward compatibility

**PyO3 Compatibility Note:**
These tests use module-scoped fixtures to prevent PyO3 reinitialization errors. FileKeyStore uses the `cryptography` library (PyO3/Rust bindings), which can only initialize once per interpreter process. See [docs/PYO3_TESTING_BEST_PRACTICES.md](PYO3_TESTING_BEST_PRACTICES.md) for details.

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

### Current Coverage (v0.2.4)

The test suite provides excellent coverage across all modules:

| Module | Coverage | Details |
|--------|----------|---------|
| `didlite/__init__.py` | 100% | Complete coverage |
| `didlite/core.py` | 96% | 5 acceptable gaps (TYPE_CHECKING guards + defensive assertions) |
| `didlite/jws.py` | 99% | 1 generic exception wrapper uncovered |
| `didlite/keystore.py` | 93% | 9 acceptable gaps (abstract methods + TYPE_CHECKING guards) |
| **Overall** | **95.7%** | **15 uncovered lines (all acceptable)** |

### Coverage Policy

**Target:** ≥ 95% coverage

**Acceptable gaps** (lines that don't require testing):

1. **TYPE_CHECKING import guards** - Type hint imports only evaluated by static analyzers
   - Example: `core.py:30-32`, `keystore.py:32-34`
   - Rationale: These imports never execute at runtime; only used by mypy/pyright

2. **Abstract method placeholders** - `pass` statements in ABC base classes
   - Example: `keystore.py:76, 92, 105` (updated line numbers post-refactor)
   - Rationale: These should never execute; all concrete implementations are fully tested

3. **Defensive assertions** - Internal sanity checks for library bugs
   - Example: `core.py:234, 253` (Ed25519 key size validation)
   - Rationale: PyNaCl/cryptography guarantee correct sizes; testing would require mocking

4. **Generic exception wrappers** - Catch-all error normalization
   - Example: `jws.py:283` (ValueError wrapper for non-ValueError exceptions)
   - Rationale: Specific error paths are tested; this handles edge cases

5. **Environmental test limitations** - Code blocked by test environment issues
   - Example: `keystore.py:285-288` (FileKeyStore exception handler)
   - Rationale: Cryptography OpenSSL backend corruption in full test suite (works individually)

**Why 95.7% is excellent:**
- Security-critical code paths: **100% covered**
- Cryptographic operations: **100% covered**
- Attack prevention: **100% covered** (algorithm confusion, missing 'kid', signature tampering)
- Data integrity checks: **100% covered**
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

# Verify the token (returns header and payload as of v0.2.3)
header, verified = verify_jws(token)
print(f"Signer DID: {header['kid']}")
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
header, verified = verify_jws(token)
print(f"Immediate verification: {verified}")

# Wait for expiration
time.sleep(3)

# Verification fails
try:
    _, _ = verify_jws(token)
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

### Performance Benchmarks (v0.2.3) - 2025-12-30

***Environment: Raspberry Pi 5 8GB***

**Performance Test Results (1000 iterations each)**

| Operation | Avg Time | Throughput | Notes |
|-----------|----------|------------|-------|
| Identity Generation | 0.11ms | ~9,200/sec | No overhead from v0.2.3 changes |
| Token Creation | 0.08ms | ~13,100/sec | Includes `iat` timestamp validation |
| Token Verification | 0.24ms | ~4,200/sec | Now returns `(header, payload)` tuple |
| DID Extraction | 0.01ms | ~190,000/sec | **NEW** - Fast header parsing without signature verification |
| Custom Headers | 0.08ms | ~13,000/sec | **NEW** - Zero overhead for custom `typ`, etc. |

**Key Findings:**
- ✅ v0.2.3 header enhancements add **negligible overhead** (<0.01ms)
- ✅ `extract_signer_did()` is **~24x faster** than full verification
- ✅ All operations remain suitable for **high-throughput IoT/edge deployments**
- ✅ Ed25519 + PyNaCl's libsodium wrapper delivers excellent ARM64 performance

## Summary (v0.2.5)

- **248 tests** covering all functionality (+12 OWASP compliance tests since v0.2.4)
- **8 test categories**: Compliance, Core, Fuzzing, Integration, JWS, Keystore, OWASP Compliance, Security
- **Excellent coverage**: 95.7% overall, with 100% on security-critical code
- **Fast execution**: Full suite runs in ~12 seconds
- **3 skipped tests**: 2 resource-intensive fuzzing, 1 environmental issue

### Test Coverage Statistics

```
Total Statements: 351
Covered: 336
Missing: 15 (all acceptable per coverage policy)
Coverage: 95.7%
```

### Test Results

```
245 passed, 3 skipped
0 failures
```

### Coverage by Priority

- **Security-critical code**: 100% (cryptographic operations, key validation, attack prevention)
- **Attack surfaces**: 100% (algorithm confusion, missing 'kid', signature tampering, token replay)
- **Data integrity**: 100% (corruption detection, validation, expiration)
- **Business logic**: 97%+ (all core functionality)
- **Defensive code**: Partially covered (acceptable gaps documented)

For questions or issues with testing, refer to the main README.md or open an issue on Gitea.
