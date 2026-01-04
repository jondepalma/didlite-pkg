# Contributing to didlite

Thank you for considering contributing to didlite! This document outlines the process for contributing.

## ⚠️ Security Policy

**DO NOT** open public issues for security vulnerabilities. See [SECURITY.md](.github/SECURITY.md) for our coordinated disclosure policy and PGP contact.

## 🔒 Security Hardening

didlite has undergone comprehensive internal security hardening with 23+ security fixes across critical, high, medium, and low severity issues. All security-related issues are tagged with the `security` label for easy filtering and review:

**[View All Closed Security Issues](https://github.com/jondepalma/didlite-pkg/issues?q=is%3Aissue+is%3Aclosed+label%3Asecurity)**

**Key Security Milestones:**
- ✅ **CRIT-1 through CRIT-4:** Critical input validation fixes (seed validation, DID resolution, multicodec validation)
- ✅ **HIGH-1 through HIGH-2:** High-severity JWS verification fixes (segment validation, base64 padding)
- ✅ **MED-1 through MED-5:** Medium-severity hardening (type validation, path traversal protection, exception sanitization)
- ✅ **LOW-1 through LOW-3:** Low-severity information disclosure fixes (error message sanitization)
- ✅ **RFC Compliance:** Full RFC 7515/7517/7519 JWT/JWS compliance test suite
- ✅ **W3C Compliance:** W3C DID Core specification compliance test suite
- ✅ **Atomic Operations:** Race condition fixes in FileKeyStore
- ✅ **Future-Dated Token Protection:** `iat` (issued-at) validation

For detailed findings and remediation, see the closed issues tagged with `v0.2-hardening` and `v0.2.2-sec-phase5`.

## Development Philosophy

didlite follows a **"lite by design"** philosophy:
- **Zero bloat:** Only support `did:key` method (no network-based resolution)
- **Minimal dependencies:** Only PyNaCl, py-multibase, cryptography
- **Edge-first:** Optimized for Raspberry Pi, IoT devices, AI agents
- **Standards compliance:** W3C DID Core, RFC 7515/7517/7519

Before proposing features, ask: "Does this align with the 'lite' philosophy?"

## Getting Started

1. **Fork the repository** and clone your fork
2. **Install in development mode:**
   ```bash
   pip install -e ".[test]"
   ```
3. **Run the test suite:**
   ```bash
   pytest -v
   pytest --cov=didlite --cov-report=term-missing
   ```

## Contribution Workflow

### For Bug Fixes

1. **Create GitHub issue** describing the bug
2. **Create a branch:** `git checkout -b fix/issue-<number>-description`
3. **Write a failing test** that reproduces the bug
4. **Fix the bug** and ensure all tests pass
5. **Update CHANGELOG.md** under "Unreleased" section
6. **Submit PR** referencing the issue number

### For New Features

1. **Open a discussion issue** first to validate the feature aligns with project goals
2. **Get maintainer approval** before implementing
3. **Create feature branch:** `git checkout -b feature/issue-<number>-description`
4. **Implement with tests** (aim for >95% coverage of new code)
5. **Update documentation** (README, docstrings, examples)
6. **Submit PR** with comprehensive description

### For Plugin Development

If you're building a plugin (e.g., `didlite-yourplugin`):
- **Use composition over inheritance:** Wrap `AgentIdentity`, don't subclass
- **Keep core didlite dependency minimal:** Don't add bloat to core
- **Follow existing plugin patterns:** See didlite-ap2, didlite-oauth, didlite-siop designs
- **Consider opening an issue** to coordinate with other plugin developers

## Code Standards

### Testing Requirements

- **All new code must have tests** (unit, integration, security)
- **Maintain >95% code coverage** for new contributions
- **Regression tests required** for bug fixes
- **Security-critical paths need 100% branch coverage**

### Code Quality

- **Follow PEP 8** (use `black` for formatting if desired)
- **Type hints encouraged** (but not required for all code)
- **Docstrings required** for public API functions
- **Keep functions focused:** Single responsibility principle

### Commit Message Format

```
<type>: <short summary>

<detailed description>

Resolves #<issue_number>

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

**Types:** `fix`, `feat`, `docs`, `test`, `refactor`, `chore`

## Testing Guidelines

### Running Tests

```bash
# All tests
pytest -v

# With coverage
pytest --cov=didlite --cov-report=term-missing

# Specific test file
pytest tests/test_core.py -v

# Fuzzing tests (full mode)
DIDLITE_FULL_FUZZ=1 pytest tests/test_fuzzing.py -v
```

### Writing Tests

- **Security tests:** Add to `tests/test_security.py`
- **Compliance tests:** Add to `tests/test_compliance.py`
- **Regression tests:** Reference issue number in test name/docstring
- **Fuzzing tests:** Use `hypothesis` for property-based testing

## Documentation

- **Update README.md** for user-facing changes
- **Update CHANGELOG.md** for all changes (follow Keep a Changelog format)
- **Add docstrings** for new public API functions
- **Update examples** if behavior changes

## Pull Request Process

1. **Ensure all tests pass** locally before submitting
2. **Update documentation** (README, CHANGELOG, docstrings)
3. **Write clear PR description:**
   - What problem does this solve?
   - How does it solve it?
   - Any breaking changes?
   - Test coverage?
4. **Wait for CI/CD** (GitHub Actions will run tests)
5. **Address review feedback** promptly
6. **Squash commits** before merge (if requested)

## Review Process

- **Maintainer review required** for all PRs
- **Security review required** for cryptographic or validation changes
- **Breaking changes require discussion** and major version bump planning

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## Questions?

- **General questions:** Open a GitHub Discussion
- **Security concerns:** Email security@didlite.io (PGP key in `.github/security/`)
- **Feature proposals:** Open an issue with `[RFC]` prefix

Thank you for contributing to didlite! 🎉
