# didlite Manual Test Scenarios

This directory contains executable Python scripts for manually testing didlite functionality. These scripts correspond to the manual testing scenarios documented in [TESTING_GUIDE.md](../TESTING_GUIDE.md).

## Prerequisites

Ensure you have didlite installed in editable mode with test dependencies:

```bash
# From the project root
pip install -e ".[test]"
```

## Running the Tests

Execute the scripts in order from the project root:

```bash
# Run all scenarios
python docs/manual_tests/01_basic_identity_and_token.py
python docs/manual_tests/02_persistent_identity_filestore.py
python docs/manual_tests/03_token_expiration.py
python docs/manual_tests/04_jwk_export_to_authlib.py
python docs/manual_tests/05_pem_export_for_openssl.py

# Or make them executable and run directly
chmod +x docs/manual_tests/*.py
./docs/manual_tests/01_basic_identity_and_token.py
```

## Test Scenarios

### 01 - Basic Identity and Token Creation
**Purpose:** Verify core functionality of identity generation, DID creation, and JWS token signing/verification.

**What it tests:**
- Creating a new ephemeral identity
- Generating a W3C-compliant DID
- Creating and verifying JWS tokens

**Expected output:** DID string, token, and verified payload.

---

### 02 - Persistent Identity with FileKeyStore
**Purpose:** Verify encrypted file-based key storage and identity persistence across sessions.

**What it tests:**
- FileKeyStore initialization with password
- Creating persistent identity
- Loading existing identity (simulated restart)
- Cross-session signature verification

**Expected output:** Matching DIDs across two sessions.

---

### 03 - Token Expiration
**Purpose:** Verify time-based token expiration using TTL (time-to-live).

**What it tests:**
- Creating tokens with `expires_in` parameter
- Immediate verification (before expiration)
- Verification after expiration (should fail)

**Expected output:** Successful verification followed by expiration error after 3 seconds.

**Note:** This test takes ~3 seconds to complete due to the expiration wait.

---

### 04 - JWK Export to Authlib
**Purpose:** Verify interoperability with the authlib library (RFC 7517 JWK compliance).

**What it tests:**
- Exporting didlite public key as JWK
- Importing JWK into authlib
- Verifying didlite-created tokens with authlib

**Expected output:** Successful cross-library token verification.

**Requirements:** authlib must be installed (included in test dependencies).

---

### 05 - PEM Export for OpenSSL
**Purpose:** Verify PEM format export for use with standard cryptographic tools.

**What it tests:**
- Exporting private key as PEM (PKCS8 format)
- Exporting public key as PEM (SubjectPublicKeyInfo format)
- PEM format validation
- PEM import roundtrip

**Expected output:** Valid PEM-formatted keys and successful roundtrip.

**Note:** PEM files can be inspected with OpenSSL:
```bash
openssl pkey -in private.pem -text -noout
openssl pkey -pubin -in public.pem -text -noout
```

## Troubleshooting

### Import errors
If you see `ImportError: No module named 'didlite'`:
```bash
pip install -e .
```

### Missing authlib
If Scenario 04 fails with authlib import error:
```bash
pip install authlib
# or
pip install -e ".[test]"
```

### Permission errors (Scenario 02)
If FileKeyStore tests fail with permission errors:
```bash
# Ensure you have write access to /tmp
ls -ld /tmp
```

## Integration with Automated Tests

These manual scenarios complement the automated pytest suite:
- **Automated tests** (`tests/`): Unit and integration tests for CI/CD
- **Manual tests** (`docs/manual_tests/`): End-to-end scenarios for exploration and demonstration

Run the automated test suite:
```bash
pytest -v
pytest --cov=didlite --cov-report=term-missing
```

## Adding New Scenarios

When adding new manual test scenarios:

1. Create a new script following the naming convention: `##_descriptive_name.py`
2. Include a docstring explaining what the scenario tests
3. Add clear console output with step numbers and checkmarks (✓)
4. Handle cleanup (temp files, directories, etc.)
5. Update this README with the new scenario

## References

- [TESTING_GUIDE.md](../TESTING_GUIDE.md) - Comprehensive testing documentation
- [verify_test.py](../verify_test.py) - Quick verification script
- [tests/](../../tests/) - Automated test suite
