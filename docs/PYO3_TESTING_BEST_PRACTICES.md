# PyO3 Testing Best Practices for didlite

This document provides guidelines for writing tests that interact with Python modules using PyO3 (Rust bindings), specifically for the `cryptography` library used by `FileKeyStore`.

## Background

### What is PyO3?

PyO3 is a Rust library that enables writing native Python modules in Rust. Many modern Python cryptography libraries (including `cryptography`) use PyO3 for performance-critical operations.

### The PyO3 Limitation

**CRITICAL**: PyO3 modules can only be initialized **once per interpreter process**.

When a PyO3 module is imported multiple times within the same Python process, you'll encounter:

```
ImportError: PyO3 modules compiled for CPython 3.8 or older may only be initialized once per interpreter process
```

This error occurs even on Python 3.9+ if you attempt to re-import the module after it has already been loaded.

## How This Affects didlite

### FileKeyStore and Cryptography

`FileKeyStore` uses the `cryptography` library for:
- PBKDF2-HMAC-SHA256 key derivation
- Fernet authenticated encryption

The cryptography library imports PyO3 modules when:
1. `FileKeyStore` is instantiated (lazy loading via `_ensure_crypto_imported()`)
2. `FileKeyStore.save_seed()` or `FileKeyStore.load_seed()` is called

### Previous Fix (Issue #50)

In v0.2.4, we fixed PyO3 errors by:
- Adding `--import-mode=importlib` to pytest configuration
- Using instance-level lazy loading (import in `__init__`, store as instance attributes)

This worked for most tests but **not for tests that create multiple FileKeyStore instances**.

## Testing Guidelines

### Rule 1: Use Module-Scoped Fixtures for FileKeyStore

**NEVER** create multiple FileKeyStore instances in the same test module using `setup_method()` or `setUp()`.

❌ **WRONG** (causes PyO3 error):
```python
class TestFileKeyStore:
    def setup_method(self):
        self.test_dir = tempfile.mkdtemp()
        self.store = FileKeyStore(self.test_dir, "password")  # NEW instance per test!

    def test_save_seed(self):
        self.store.save_seed("test", os.urandom(32))

    def test_load_seed(self):
        self.store.save_seed("test", os.urandom(32))
        # This test creates ANOTHER FileKeyStore, triggering PyO3 error
```

✅ **CORRECT** (module-scoped fixture):
```python
@pytest.fixture(scope="module")
def shared_test_dir():
    test_dir = tempfile.mkdtemp()
    yield test_dir
    shutil.rmtree(test_dir)

@pytest.fixture(scope="module")
def shared_keystore(shared_test_dir):
    """
    Module-level fixture prevents PyO3 reinitialization.
    All tests share the same FileKeyStore instance.
    """
    return FileKeyStore(shared_test_dir, "test_password")

class TestFileKeyStore:
    def test_save_seed(self, shared_keystore, shared_test_dir):
        shared_keystore.save_seed("test1", os.urandom(32))

    def test_load_seed(self, shared_keystore, shared_test_dir):
        seed = os.urandom(32)
        shared_keystore.save_seed("test2", seed)
        loaded = shared_keystore.load_seed("test2")
        assert loaded == seed
```

### Rule 2: Use Unique Identifiers per Test

When sharing a FileKeyStore instance, use unique identifiers for each test to avoid conflicts:

```python
def test_salt_length(self, shared_keystore, shared_test_dir):
    shared_keystore.save_seed("test_salt_length", os.urandom(32))  # Unique ID

def test_salt_random(self, shared_keystore, shared_test_dir):
    shared_keystore.save_seed("test_salt_random1", os.urandom(32))  # Unique ID
    shared_keystore.save_seed("test_salt_random2", os.urandom(32))  # Unique ID
```

### Rule 3: Document PyO3 Constraints in Test Modules

Always add a docstring explaining why module-scoped fixtures are used:

```python
"""
IMPORTANT: PyO3 Compatibility Note
----------------------------------
This test module uses module-scoped fixtures to avoid PyO3 reinitialization errors.
FileKeyStore imports cryptography modules which use PyO3 (Rust bindings).
PyO3 modules can only be initialized once per interpreter process.

By sharing a single FileKeyStore instance across all tests in this module,
we prevent multiple cryptography imports within the same test session.

Reference: Issue #50 - CI/CD Pipeline Fixes: PyO3 Compatibility
"""
```

### Rule 4: Avoid Creating FileKeyStore in Test Bodies

❌ **WRONG**:
```python
def test_iteration_count():
    store1 = FileKeyStore("/tmp/test1", "pass1")  # First import
    assert store1.iterations == 480000

    store2 = FileKeyStore("/tmp/test2", "pass2")  # PyO3 ERROR!
```

✅ **CORRECT**:
```python
def test_iteration_count(shared_keystore):
    assert shared_keystore.iterations == 480000
```

### Rule 5: Use Session-Scoped Fixtures for Cross-Module Sharing

If multiple test modules need FileKeyStore, use session scope in `conftest.py`:

```python
# conftest.py
import pytest
import tempfile
import shutil
from didlite.keystore import FileKeyStore

@pytest.fixture(scope="session")
def session_test_dir():
    test_dir = tempfile.mkdtemp()
    yield test_dir
    shutil.rmtree(test_dir)

@pytest.fixture(scope="session")
def session_keystore(session_test_dir):
    """
    Session-level fixture for FileKeyStore.
    Shared across ALL test modules in the session.
    """
    return FileKeyStore(session_test_dir, "test_password")
```

## Examples

### Good Example: test_owasp_compliance.py

```python
@pytest.fixture(scope="module")
def shared_keystore(shared_test_dir):
    return FileKeyStore(shared_test_dir, "test_password")

class TestOWASPCompliance:
    def test_salt_length_128_bits(self, shared_keystore, shared_test_dir):
        seed = os.urandom(32)
        shared_keystore.save_seed("test_salt_length", seed)
        # ... verify salt

    def test_salt_is_random(self, shared_keystore, shared_test_dir):
        seed = os.urandom(32)
        shared_keystore.save_seed("test_salt_random1", seed)
        shared_keystore.save_seed("test_salt_random2", seed)
        # ... verify salts are different
```

### Bad Example: What NOT to Do

```python
class TestFileKeyStore:
    def test_save_and_load(self):
        # DON'T DO THIS - creates new instance per test
        store = FileKeyStore("/tmp/test1", "password")
        store.save_seed("test", os.urandom(32))

    def test_wrong_password(self):
        # PyO3 ERROR HERE - second FileKeyStore instance
        store = FileKeyStore("/tmp/test2", "password")
        # ...
```

## Debugging PyO3 Errors

### Identifying the Issue

If you see:
```
ImportError: PyO3 modules compiled for CPython 3.8 or older may only be initialized once per interpreter process
```

1. **Check test class structure**: Do you have `setup_method()` or `setUp()` creating FileKeyStore?
2. **Check test bodies**: Are you creating FileKeyStore instances directly in test methods?
3. **Check fixture scope**: Are you using method-scoped fixtures for FileKeyStore?

### Quick Fix Checklist

- [ ] Replace `setup_method()` with module-scoped `@pytest.fixture(scope="module")`
- [ ] Move FileKeyStore instantiation to fixture
- [ ] Pass fixture to test methods as parameters
- [ ] Use unique identifiers for each test operation
- [ ] Add PyO3 compatibility docstring to test module

## Why Python 3.10 Specifically?

The error often manifests in Python 3.10 due to subtle differences in how pytest imports modules and manages test discovery. While the underlying PyO3 limitation exists in all Python versions, Python 3.10's specific import mechanics make it more likely to trigger during CI/CD.

## CI/CD Considerations

### GitHub Actions

Our `.github/workflows/test.yml` runs tests across Python 3.9-3.12 using a **separated workflow structure** to prevent PyO3 conflicts:

**Workflow Structure (v0.2.5+):**
1. **Main `test` job**: Runs all tests EXCEPT OWASP compliance tests
   - Command: `pytest --ignore=tests/test_owasp_compliance.py`
   - Prevents PyO3 exhaustion from test_keystore.py (20+ FileKeyStore instances)

2. **Isolated `owasp-compliance` job**: Runs ONLY OWASP compliance tests
   - Command: `pytest tests/test_owasp_compliance.py -v`
   - Fresh interpreter prevents cross-module PyO3 conflicts

**Rationale**: While module-scoped fixtures prevent PyO3 errors within a single test module, multiple test modules creating FileKeyStore instances (e.g., test_keystore.py runs before test_owasp_compliance.py alphabetically) can exhaust PyO3 initialization before later tests run.

**Future Plan**: v0.3.0 will refactor ALL FileKeyStore tests to use module-scoped fixtures, allowing consolidated workflow.

**Pytest Configuration** (in `pyproject.toml`):
```toml
[tool.pytest.ini_options]
addopts = "-v --strict-markers --import-mode=importlib"
```

The `--import-mode=importlib` flag is **required** for PyO3 compatibility.

## Summary

**Golden Rule**: When testing FileKeyStore, **always use module or session-scoped pytest fixtures**. Never create multiple FileKeyStore instances in the same test session.

This prevents PyO3 reinitialization errors and ensures tests pass consistently across all Python versions in CI/CD.

---

## References

- **Issue #50**: CI/CD Pipeline Fixes: Python 3.8 Drop, License Format, PyO3 Compatibility
- **PyO3 GitHub Issue**: https://github.com/pytest-dev/pytest/issues/7856
- **Pytest Fixtures Documentation**: https://docs.pytest.org/en/stable/fixture.html#scope-sharing-fixtures-across-classes-modules-packages-or-session

---

**Last Updated:** 2026-01-08
**Applies to:** didlite v0.2.5+
