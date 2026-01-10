# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.5] - 2026-01-09

### Added
- **GitHub CODEOWNERS file** for automated review requests
  - Defines code ownership for security-critical components
  - Auto-assigns @jondepalma as reviewer on all PRs
  - Special attention to core library, security tests, and release scripts
- **Dependabot configuration** for automated dependency monitoring
  - Weekly scans for Python dependencies (pynacl, py-multibase, test deps)
  - Weekly scans for GitHub Actions version updates
  - PRs target `dev` branch to maintain dev → main workflow
  - Groups minor/patch updates, separates major updates for careful review
  - Auto-assigns security labels for triage

### Changed
- **Moved SETUP_LOCAL.md to internal documentation** (#54)
  - Package now available on PyPI, local setup guide no longer needed in public docs
  - Moved to docs/dev-design/ (gitignored internal documentation)

### Fixed
- **PyO3 reinitialization error in OWASP compliance tests**
  - Fixed tests/test_owasp_compliance.py to use module-scoped fixtures
  - Prevents multiple FileKeyStore instantiations causing cryptography reimports
  - Error occurred in Python 3.9/3.10 CI environments
  - **Root cause**: Multiple test modules creating FileKeyStore instances exhausted PyO3 initialization
  - **Interim solution**: Separated OWASP tests into isolated CI job (prevents cross-module conflicts)
  - **Long-term fix**: v0.3.0 will refactor all FileKeyStore tests to use module-scoped fixtures
  - Reference: Issue #50 - CI/CD Pipeline Fixes: PyO3 Compatibility
- **Documentation accuracy for PBKDF2 iteration count** (#55)
  - Corrected docs/CRYPTO_RATIONALE.md to reflect actual implementation (480,000 iterations)
  - Corrected docs/THREAT_MODEL.md to reflect actual implementation (480,000 iterations)
  - Documentation previously claimed 600,000 iterations (aspirational, never implemented)
  - Actual implementation uses 480,000 iterations since v0.1.5
  - **Compliance**: Exceeds OWASP 2021 (310,000) by 55%, ~80% of OWASP 2023 (600,000)
  - **Security**: Sufficient for production with strong passwords (20+ characters)
  - No code changes - documentation-only fix
- **Release script CHANGELOG duplication bug** (#52)
  - scripts/release.sh now checks if version header exists before inserting
  - Re-running release script no longer duplicates version headers
  - If version exists, only the date is updated

### Added
- **OWASP Password Storage Compliance Test Suite** (#55)
  - New tests/test_owasp_compliance.py with 12 comprehensive tests
  - Validates PBKDF2-HMAC-SHA256 implementation against OWASP recommendations
  - Tests verify iteration count, salt randomness/length, HMAC algorithm
  - Validates documentation claims in CRYPTO_RATIONALE.md and THREAT_MODEL.md
  - Total test count: 245 → 257 tests (4.9% increase)

### Changed
- **CI/CD workflow restructured to prevent PyO3 conflicts**
  - Split test suite into separate GitHub Actions jobs
  - Main `test` job: Runs all tests except OWASP compliance (`--ignore=tests/test_owasp_compliance.py`)
  - New `owasp-compliance` job: Runs OWASP tests in isolated environment
  - **Rationale**: PyO3 modules can only initialize once per interpreter process
  - Prevents test_keystore.py (20+ FileKeyStore instances) from exhausting PyO3 before OWASP tests run
  - **Temporary solution** pending v0.3.0 comprehensive test refactoring
  - Both jobs run on Python 3.9-3.12 matrix

### Documentation
- **Added .github/SECURITY.md password requirements section** (#55)
  - Documents 480,000 iteration count and OWASP compliance status
  - Provides strong password guidance (20+ characters mandatory)
  - Includes GPU crack time analysis for different password strengths
  - Documents v1.0.0 upgrade plan (600,000 iterations with backward compatibility)

## [0.2.4] - 2025-12-31

### ⚠️ BREAKING CHANGES
- **Python 3.8 support dropped** - Minimum version now Python 3.9+ (#50)
  - **Rationale**: Python 3.8 reached EOL in October 2024 (no security patches)
  - **Technical blocker**: Type hint incompatibility (`tuple[dict, dict]` requires PEP 585)
  - **Migration**: Upgrade to Python 3.9 or newer
  - **Target platforms**: Raspberry Pi OS Bullseye (3.9), Bookworm (3.11), AWS Graviton (3.9+)

### Added
- **CI/CD pipeline with GitHub Actions** (#50)
  - Multi-version testing (Python 3.9, 3.10, 3.11, 3.12) on every PR/push
  - Fuzzing tests with hypothesis (30-minute timeout in CI)
  - Security scanning with pip-audit (OSV database)
  - Codecov integration for coverage reporting
- **OIDC-authenticated PyPI publishing** - Secure publishing without API tokens (#50)
  - Trusted Publisher configuration via GitHub OIDC
  - Automated build and verification with twine
  - Triggers on GitHub release publication
- **Modern Python packaging (PEP 517/518)** (#50)
  - Complete pyproject.toml configuration with metadata
  - Centralized pytest and coverage configuration
  - setup.py converted to minimal shim for backwards compatibility
- **Release automation script** (`scripts/release.sh`) (#50)
  - Automated version bumping in pyproject.toml and `__init__.py`
  - CHANGELOG.md date stamping
  - Git tagging and GitHub release creation
  - Branch enforcement (must run on main)
- **Community contribution guidelines** (#50)
  - CONTRIBUTING.md with security hardening documentation
  - CODE_OF_CONDUCT.md (Contributor Covenant v2.0)
  - Reference to 23+ security fixes with GitHub issue links
- **Supply chain security documentation** (#50)
  - SLSA Level 2 compliance status documented in SECURITY.md
  - SLSA Level 3 roadmap for v1.0.0 (provenance, hermetic builds, dependency pinning)
  - Dependency vulnerability scanning policy (48-hour SLA for critical issues)

### Changed
- **PyO3 compatibility fixes** - Resolved reinitialization errors across all Python versions (#50)
  - Implemented module-level lazy singleton pattern for cryptography imports
  - Affects: `didlite/keystore.py` and `didlite/core.py`
  - Preserves lazy loading philosophy (no imports unless FileKeyStore/PEM methods used)
  - **Root cause**: PyNaCl's cryptography dependency uses PyO3 (Rust bindings), which can only initialize once per process
- **Removed deprecated backend parameter** from `load_pem_private_key()` (#50)
  - Deprecated in cryptography v36.0.0 (November 2021)
  - Backend now auto-selected by cryptography library
  - Zero functionality changes
- **Test coverage infrastructure** - Statement count increased due to lazy singleton helpers (#50)
  - v0.2.3: 321 statements, 312 covered (97.2%)
  - v0.2.4: 351 statements, 336 covered (95.7%)
  - **Net change**: +30 statements (+24 covered, +6 missing)
  - All security-critical code remains 100% covered
  - New infrastructure code: TYPE_CHECKING guards, singleton logic

### Fixed
- **Python 3.9-3.12 compatibility** - All tests pass on supported versions (#50)
  - Added `from __future__ import annotations` for PEP 585 compatibility
  - Fixed pytest import mode conflicts with PyO3 bindings
  - Removed license classifier conflict (setuptools >=77.0.0 compliance)

### Documentation
- **Updated test coverage metrics** for v0.2.4 in README.md and docs/TESTING_GUIDE.md (#50)
  - Documented acceptable coverage gaps (TYPE_CHECKING guards, abstract methods, defensive assertions)
  - Explained infrastructure code coverage trade-offs

### Removed
- **Python 3.8 support** - No longer tested or supported (#50)

## [0.2.3] - 2025-12-30

### ⚠️ BREAKING CHANGES
- **`verify_jws()` now returns `(header, payload)` tuple instead of just `payload`** (#32)
  - **Migration**: Change `payload = verify_jws(token)` to `_, payload = verify_jws(token)`
  - **Benefit**: Access to header information (kid, alg, typ, iat) without re-parsing
  - **Impact**: ~10 usage sites in didlite-examples, ~200+ test cases updated
  - See [docs/dev-design/VERIFY_JWS_CHANGE.md](docs/dev-design/VERIFY_JWS_CHANGE.md) for full migration guide

### Added
- **Custom JWS headers support** - `create_jws()` accepts `headers` parameter (#43)
  - Enables custom `typ` headers for plugin ecosystems (AP2, OAuth, SIOP)
  - Protected fields: `alg`, `kid`, `iat` cannot be overridden (security-critical)
  - Example: `create_jws(agent, payload, headers={"typ": "dpop+jwt"})`
  - **Unblocks**: didlite-ap2, didlite-oauth, didlite-siop plugin implementations
- **`extract_signer_did()` helper function** - Fast DID extraction without verification (#44)
  - Useful for routing, logging, rate limiting before expensive signature verification
  - WARNING: Does NOT verify signature - always call `verify_jws()` for security decisions
  - Performance: ~2x faster than `verify_jws()` for DID-only extraction
- **Header timestamp (`iat`) now included in JWS header** (#43)
  - Both header and payload contain `iat` claim for audit trail
  - Enables header-based timestamp validation in plugins

### Added - Test Coverage
- **31 new regression tests for v0.2.3 features** (#32, #43, #44, #46)
  - 19 tests for JWS header enhancements (custom headers, tuple return, extract_signer_did)
  - 11 tests for Issue #46 coverage gaps (VULN-3, FileKeyStore, EnvKeyStore edge cases)
  - 1 test for missing 'kid' header validation (security-critical path)
- **Coverage improvement**: 96% → 97.2% (9 fewer uncovered lines)
  - jws.py: 97% → 99% coverage (missing 'kid' header path now tested)
- **Total test count**: 205 → 233 tests (13.7% increase)

### Changed
- **All existing tests updated** for `verify_jws()` tuple return (203 tests across 5 files)
  - Pattern: `verified = verify_jws(token)` → `_, verified = verify_jws(token)`
  - Files updated: test_jws.py, test_compliance.py, test_fuzzing.py, test_integration.py, test_security.py

### Fixed
- Issue #46: Added missing test coverage for:
  - VULN-3 lazy import verification (cryptography not loaded until needed)
  - FileKeyStore exception paths (corrupted JSON, missing fields, write failures)
  - EnvKeyStore edge cases (invalid base64, wrong length, nonexistent variables)
- **Test reliability improvements**:
  - Fixed flaky signature validation test that could fail with single-character tampering
  - Improved signature corruption test to modify multiple bytes for reliable detection
  - Added specific exception type checking (BadSignatureError instead of generic Exception)
  - Documented cryptography OpenSSL backend issue affecting permission error test in full suite

### Plugin Ecosystem Readiness
This release unblocks three planned plugin packages:
- **didlite-ap2**: Agent Payment Protocol (mandate signing with custom headers)
- **didlite-oauth**: OAuth/OIDC integration (DPoP tokens with custom typ)
- **didlite-siop**: Self-Issued OpenID Provider v2 (SIOP ID tokens)

All plugins require `didlite>=0.2.3` for custom header support and tuple return values.

### Migration Guide
**For applications using `verify_jws()`:**

```python
# BEFORE (v0.2.2)
payload = verify_jws(token)
message = payload['message']

# AFTER (v0.2.3) - Option 1: Ignore header
_, payload = verify_jws(token)
message = payload['message']

# AFTER (v0.2.3) - Option 2: Use header
header, payload = verify_jws(token)
signer_did = header['kid']
message = payload['message']
```

**Automated migration** for didlite-examples:
```bash
sed -i 's/payload = verify_jws(/_, payload = verify_jws(/g' *.py
sed -i 's/verified = verify_jws(/_, verified = verify_jws(/g' *.py
```

### References
- Issue #32: Change verify_jws() to return both header and payload
- Issue #43: Add optional headers parameter to create_jws()
- Issue #44: Add extract_signer_did() helper function
- Issue #46: Expand test coverage for Phase 5 regression tests
- Design doc: [docs/dev-design/VERIFY_JWS_CHANGE.md](docs/dev-design/VERIFY_JWS_CHANGE.md)
- Planning doc: [docs/dev-design/PHASE_5_IMPLEMENTATION_PLAN.md](docs/dev-design/PHASE_5_IMPLEMENTATION_PLAN.md)

---

## [0.2.2] - 2025-12-29

### Security
- **Phase 5 Security Hardening - 7 vulnerability fixes** (#33-#39)
  - **VULN-1**: DoS prevention with DID length limit (128 chars) and type validation (#33)
  - **VULN-2**: Fixed base64 padding calculation for JWK import (RFC 7517 compliance) (#34)
  - **VULN-3**: Lazy imports for `cryptography` dependency (lite philosophy) (#35)
  - **VULN-4**: Algorithm enforcement - prevent "None Algorithm" JWT attacks (RFC 7515) (#36)
  - **VULN-5**: Compact JSON serialization for JWS (RFC 7515 compliance) (#37)
  - **VULN-6**: Future-dating protection with 60s clock skew tolerance (RFC 7519) (#38)
  - **VULN-7**: Atomic file creation with secure permissions (0o600) - TOCTOU fix (#39)

### Added
- **Comprehensive compliance test suite** (`tests/test_compliance.py`) (#40)
  - 75 tests validating W3C DID Core and RFC JWT/JWS standards
  - Coverage: DID Method, DID Resolution, JWK, JWS, JWT claims validation
- **Phase 5 regression tests** - 19 tests preventing vulnerability reintroduction (#41-#45)
  - `TestPhase5CoreRegressions`: VULN-1, VULN-2 (5 tests)
  - `TestPhase5SecurityRegressions`: VULN-4, VULN-5, VULN-6 (9 tests)
  - `TestPhase5KeystoreRegressions`: VULN-7 (5 tests including threading race condition test)
- **Regression testing strategy** in CLAUDE.md (#44)
  - When to add regression tests (5 criteria)
  - Where to add tests (file-specific guidance)
  - Test coverage goals (100% security-critical paths)

### Changed
- **Extended lazy imports to keystore.py** (VULN-3 fix)
  - `cryptography` now imported only when FileKeyStore methods called
  - MemoryKeyStore and EnvKeyStore work without `cryptography` installed
  - Maintains "lite" philosophy for edge deployments

### Test Suite Growth
- **v0.2.1**: 101 tests
- **v0.2.2**: 205 tests (103% increase)
- **Coverage**: 95% → 96% (288/299 lines)
- **New test categories**:
  - 75 compliance tests (W3C DID Core, RFC 7515/7517/7519)
  - 19 Phase 5 regression tests
  - 1 threading race condition test (TOCTOU verification)

### Fixed
- Base64 padding formula: `"=" * (-len(data) % 4)` (was adding 4 '=' when len%4==0)
- File permissions race condition in FileKeyStore (atomic creation with 0o600)
- Algorithm substitution attack vectors (enforce EdDSA-only)
- Future-dated token acceptance (prevent replay attacks)

### Documentation
- Added regression testing strategy to CLAUDE.md
- All security fixes reference specific issues (#33-#39) and PHASE_5_FINDINGS.md

### References
- PHASE_5_FINDINGS.md - Detailed vulnerability analysis
- Issues #33-#39 - Individual vulnerability tickets
- Issue #40 - Compliance test suite
- Issues #41-#45 - Regression test implementation
- Issue #46 - Future test coverage improvements (v0.2.3)

## [0.2.1] - 2025-12-26

### Fixed
- **Added missing `cryptography` dependency to setup.py** (#30)
  - Package was importing from `cryptography` but not declaring it as a dependency
  - Caused `ModuleNotFoundError` when installed in fresh environments
  - Added `cryptography>=41.0.0` to `install_requires`
  - Required for PEM export/import (`to_pem()`, `from_pem()`) and keystore encryption
  - **CRITICAL**: This is a patch release to fix broken installations

## [0.2.0] - 2025-12-26

### Changed
- **JWS verification now raises native exception types** (#21)
  - `verify_jws()` no longer wraps exceptions in generic `Exception`
  - Returns specific exception types for better error handling:
    - `BadSignatureError`: Signature verification failed
    - `ValueError`: Token format invalid, expired, or DID invalid
    - `json.JSONDecodeError`: Header or payload contains invalid JSON
  - Improves debuggability while maintaining error message sanitization (Issue #11)
  - **BREAKING CHANGE**: Applications catching generic `Exception` must update to catch specific types
  - Not a concern for v0.2.0 (library not yet public)
- **Optimized fuzzing suite for Raspberry Pi** (#21)
  - Reduced examples from 50 to 10 on resource-constrained devices
  - Disabled shrinking phase to reduce CPU/memory usage
  - Added `DIDLITE_FULL_FUZZ` environment variable for CI/CD (500 examples with shrinking)
  - Full suite now completes in ~30 seconds on Raspberry Pi 5 (was timing out)
  - CI/CD environments can run comprehensive fuzzing with `export DIDLITE_FULL_FUZZ=1`

### Documentation
- Added `docs/CI_CD_FUZZING.md` with fuzzing configuration guide for CI/CD pipelines

## [0.1.5] - 2025-12-23

### Added
- **Apache 2.0 LICENSE** file with proper copyright notice
- **License headers** to all Python source files (core.py, jws.py, keystore.py, __init__.py)
- **JWK and PEM export/import support** (#4)
  - `to_jwk()` and `from_jwk()` methods for JSON Web Key format
  - `to_pem()` and `from_pem()` methods for PEM format (PKCS8/SubjectPublicKeyInfo)
  - Full roundtrip consistency and cross-format compatibility
- **TTL expiration support** for JWS tokens (#5)
  - Optional `expires_in` parameter (seconds from now)
  - Optional `exp` parameter (absolute Unix timestamp)
  - Automatic `iat` (issued at) claim for audit trail
  - Expiration validation in `verify_jws()`
- **Pluggable key storage abstraction** (#6)
  - Abstract `KeyStore` base class
  - `MemoryKeyStore` for testing/ephemeral use
  - `EnvKeyStore` for environment variable storage (Docker/K8s)
  - `FileKeyStore` with encrypted file storage (PBKDF2 + Fernet AES-128-CBC)
  - `AgentIdentity` integration with automatic seed persistence
- **Authlib integration tests** for interoperability validation (#7)
  - Bidirectional compatibility: didlite ↔ authlib
  - JWK export/import roundtrips
  - Cross-library signature consistency
- **Comprehensive testing documentation**
  - New `docs/TESTING_GUIDE.md` with 98% coverage policy (#12)
  - 5 executable manual test scenarios in `docs/manual_tests/`
  - Keystore types demonstration (Scenario 2.5)
- **Security audit preparation plan** (#8)
  - Comprehensive `docs/SECURITY_AUDIT.md` with 54 checklist items
  - 6 phases: Code Review, Documentation, Testing, Dependencies, Compliance, Audit Prep
  - Enhanced with fuzzing requirements, SLSA Level 3, and memory safety checks
- **Architecture diagrams** (Mermaid)
  - Component architecture showing trust boundaries
  - JWS signing flow sequence diagram
- **Gitea integration**
  - Issue templates (bug report, feature request)
  - 42-label system for issue management
  - Tea CLI workflow documentation in CLAUDE.md
- **Performance benchmarks** (Raspberry Pi 5 8GB)
  - ~11,000 identities/second generation rate
  - ~8,300 tokens/second signing rate

### Changed
- **Version bumped** from 0.1.0 to 0.1.5
- **Removed python-jose dependency** (#10)
  - Not compatible with EdDSA/Ed25519 algorithm
  - Streamlined to authlib for interoperability
  - Reduced dependency bloat
- **Enhanced test coverage** from 95% to 98% (#11)
  - Total: 101 tests (up from 15 in v0.1.0)
  - Added high/medium priority security tests
  - didlite/core.py now 100% coverage
- **Updated TESTING_GUIDE.md** with formal coverage policy
  - Documented acceptable coverage gaps (ABC placeholders, defensive handlers)
  - Coverage breakdown by module

### Fixed
- Issue template URLs updated to point to Gitea instance (http://git.jondepalma.net)

### Documentation
- Added comprehensive `docs/TESTING_GUIDE.md`
- Created `docs/SECURITY_AUDIT.md` for audit readiness
- Added `docs/diagrams/` with Mermaid architecture diagrams
- Added 5 executable manual test scenarios
- Updated README.md with performance benchmarks
- Enhanced CLAUDE.md with Gitea workflow and testing instructions

### Security
- Comprehensive security hardening in preparation for v1.0.0
- Security audit plan covering:
  - Cryptographic implementation review
  - Input validation and sanitization
  - Timing attack analysis
  - Dependency vulnerability scanning
  - SLSA Level 3 supply chain security
  - Fuzzing and property-based testing
  - W3C DID and JWT/JWS standards compliance
- FileKeyStore uses OWASP-compliant PBKDF2 iterations (480k)
- Secure file permissions (0o600) enforced
- Path traversal protection in keystore
- No known vulnerabilities in dependency tree

### Test Suite Growth
- v0.1.0: 15 tests
- v0.1.5: 101 tests (673% increase)
- Coverage: 95% → 98%
- Categories:
  - 28 core tests
  - 34 JWS tests
  - 29 keystore tests
  - 5 authlib integration tests
  - 5 manual test scenarios

## [0.1.0] - 2025-12-20

### Added
- Initial release
- Core `AgentIdentity` class for Ed25519-based DID generation
- W3C-compliant `did:key` method support
- JWS token creation and verification (`create_jws`, `verify_jws`)
- DID resolution without network calls (`resolve_did_to_key`)
- Pure Python implementation with minimal dependencies (PyNaCl, py-multibase)
- Basic test suite with pytest (15 tests)
- Documentation and usage examples

### Features
- Zero-dependency bloat design
- ARM64 native support (Raspberry Pi, AWS Graviton, M1/M2/M3 Macs)
- Standards-compliant EdDSA signatures (RFC 8032)
- Self-contained verification (DID embeds public key)
