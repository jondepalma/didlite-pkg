# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

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
