# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`didlite` is a zero-dependency-bloat Python library for generating W3C Standard Decentralized Identifiers (DIDs) using Ed25519 keys. It targets edge devices, IoT sensors, and AI agents that need cryptographically verifiable identity without requiring central servers, certificate authorities, or blockchains.

**Key Design Principle:** "Lite" by design - only supports `did:key` method to ensure maximum portability for Edge AI and IoT deployments, especially ARM64 devices (Raspberry Pi, AWS Graviton, M1/M2/M3 Macs).

## Development Methodology

This project follows the Claude Code development methodology for consistent, traceable, test-driven development.

**Core methodology:** `~/.config/claude-code/methodologies/claude-code-methodology.md`

**Key practices enforced:**
- GitHub issue created BEFORE all non-trivial work (bug fixes, enhancements, features)
- Regression tests added after EVERY fix
- Test coverage maintained/improved with every change
- Issue progress tracked via comments
- PRs include test results and coverage reports

**Project-specific patterns:**
- GitHub as primary remote (origin)
- Phase-based security regression test organization
- Comprehensive attack vector testing for cryptographic operations

**Quick reference:** See `docs/dev-design/QUICK-REFERENCE.md` for workflow cheat sheet

## Core Architecture

The library has a minimal two-module architecture:

### didlite/core.py
- `AgentIdentity`: Main identity class that wraps PyNaCl's Ed25519 signing
  - Generates or loads Ed25519 keypairs (from seed or random)
  - Derives W3C-compliant `did:key` identifiers using Multicodec (0xed01) + Multibase (base58btc)
  - Provides low-level signing interface
- `resolve_did_to_key()`: Static DID resolution (no network calls) - reverses the `did:key` encoding to extract the VerifyKey

### didlite/jws.py
- `create_jws()`: Creates compact JWS tokens (EdDSA-signed JWTs)
  - Auto-embeds the signer's DID in the `kid` header field
  - Uses base64url encoding without padding
- `verify_jws()`: Verifies signatures using the DID embedded in the token
  - Extracts DID from `kid` header, resolves to public key, verifies signature
  - Returns payload dict if valid, raises exception if tampered

**Critical Concept:** The DID itself IS the public key (encoded). No database lookups needed for verification - this is the core architectural advantage for IoT/edge deployments.

## Development Commands

### Local Development Setup
Install in editable mode for live development (changes reflected immediately without reinstall):

```bash
pip install -e .
```

For cross-project development:
```bash
# From consuming project directory
pip install -e ../didlite-pkg
```

### Testing
Install test dependencies:
```bash
pip install -e ".[test]"
```

Run the full test suite:
```bash
pytest
```

Run tests with coverage report:
```bash
pytest --cov=didlite --cov-report=term-missing
```

Run specific test file:
```bash
pytest tests/test_core.py
pytest tests/test_jws.py
```

Run tests with verbose output:
```bash
pytest -v
```

Quick verification script (without pytest):
```bash
python docs/verify_test.py
```

Expected output: Generates a new DID and signed JWS token.

### Regression Testing Strategy

**IMPORTANT**: After completing major security fixes, feature implementations, or bug fixes, always evaluate whether regression tests are needed to prevent the issue from reappearing.

**When to Add Regression Tests**:
1. After fixing security vulnerabilities (especially CRITICAL/HIGH severity)
2. After fixing bugs that could silently break functionality
3. After implementing features with security implications
4. After changes that modify core cryptographic operations
5. After changes to validation/parsing logic

**Where to Add Regression Tests**:
- `tests/test_core.py` - For core identity and DID resolution fixes
- `tests/test_jws.py` - For JWT/JWS token creation and validation fixes
- `tests/test_keystore.py` - For key storage and encryption fixes
- `tests/test_security.py` - For input validation and attack prevention
- `tests/test_compliance.py` - For standards compliance verification

**Regression Test Requirements**:
1. **Specific Issue Reference**: Test docstring must reference the issue number
2. **Attack Vector Testing**: For security fixes, test the specific attack that was prevented
3. **Edge Cases**: Test boundary conditions that triggered the bug
4. **Positive Cases**: Ensure fix doesn't break valid functionality
5. **Clear Naming**: Use pattern `test_vuln{N}_{description}` or `test_issue{N}_{description}`

**Example Workflow**:
```bash
# After implementing security fixes
pytest -v  # Verify all tests pass

# Evaluate: "Could this vulnerability reappear if someone refactors this code?"
# If yes, add regression tests

# Run specific regression test class
pytest tests/test_jws.py::TestPhase5SecurityRegressions -v

# Verify overall test count increased
pytest --co -q  # Count tests
```

**Test Coverage Goals**:
- Core functionality: 100% line coverage
- Security-critical paths: 100% branch coverage
- Attack prevention: Explicit tests for each known attack vector
- Standards compliance: Test suite for each RFC/W3C requirement

See [Phase 5 Regression Tests](tests/test_jws.py#L603) as an example of comprehensive regression test implementation.

### PyO3 Testing Best Practices

**CRITICAL**: When writing tests that use `FileKeyStore`, follow PyO3 compatibility guidelines to avoid reinitialization errors.

`FileKeyStore` uses the `cryptography` library, which has PyO3 (Rust) bindings. PyO3 modules can only be initialized **once per interpreter process**.

**Key Rules**:
1. **Use module-scoped fixtures** for `FileKeyStore` instances
2. **Never create multiple FileKeyStore instances** in the same test module using `setup_method()`
3. **Share a single FileKeyStore** across all tests using pytest fixtures
4. **Use unique identifiers** for each test operation to avoid conflicts

**Example**:
```python
@pytest.fixture(scope="module")
def shared_keystore(shared_test_dir):
    """Module-level fixture prevents PyO3 reinitialization errors"""
    return FileKeyStore(shared_test_dir, "test_password")

class TestFileKeyStore:
    def test_save_seed(self, shared_keystore):
        shared_keystore.save_seed("test_unique_id", os.urandom(32))
```

**Detailed Guide**: See [docs/PYO3_TESTING_BEST_PRACTICES.md](docs/PYO3_TESTING_BEST_PRACTICES.md) for comprehensive guidelines, examples, and troubleshooting.

### Dependencies
- `pynacl>=1.5.0` - Ed25519 signing (libsodium wrapper)
- `py-multibase>=1.0.0` - Multibase encoding for DID formatting

Test dependencies:
- `authlib>=1.0.0` - For integration tests and interoperability validation

Requires Python 3.8+

## GitHub Workflow with gh CLI

This project uses GitHub for issue tracking, pull requests, and CI/CD. The `gh` CLI is configured for seamless workflow.

### gh CLI Setup

**Installation** (Raspberry Pi / Debian-based systems):
```bash
# Install GitHub CLI
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update && sudo apt install -y gh

# Authenticate
gh auth login
```

**Prerequisites**:
- The `gh` CLI auto-detects the repository from git remotes (no need for `-R` flag when in repo directory)
- SSH authentication recommended (same key can be used as Gitea)

### Issue Management

**Create an issue**:
```bash
gh issue create --title "Issue title" --body "Detailed description of the issue"
```

**List issues**:
```bash
gh issue list              # List open issues
gh issue list --state all  # List all issues (open and closed)
```

**Close an issue**:
```bash
gh issue close <issue_number>
```

**View issue details**:
```bash
gh issue view <issue_number>
```

### Pull Request Workflow

**Standard workflow for bug fixes and features**:

1. **Work on dev branch**:
```bash
git checkout dev
# Make changes, run tests
pytest -v
```

2. **Commit changes** (following conventional commits):
```bash
git add <files>
git commit -m "fix: Brief description

Detailed explanation of the fix.

Resolves #<issue_number>

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

3. **Push to origin/dev**:
```bash
git push origin dev
```

4. **Create pull request**:
```bash
gh pr create --base main --head dev \
  --title "Brief PR title" \
  --body "## Summary
- What changed
- Why it changed
- Impact

## Test Results
<test output>

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

**List pull requests**:
```bash
gh pr list
gh pr list --state all
```

**View PR details**:
```bash
gh pr view <pr_number>
```

**Merge a PR**:
```bash
gh pr merge <pr_number>
```

### Git Workflow Best Practices

**Branch Strategy**:
- `main`: Production-ready code
- `dev`: Development branch (default for new features/fixes)
- Feature branches: Created from `dev` as needed

**Remote Strategy**:
- `origin`: GitHub (primary - used for CI/CD, issues, PRs)

**Commit Message Format**:
```
<type>: <short summary>

<detailed description>

Resolves #<issue_number>

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

**Commit Types**:
- `fix:` - Bug fixes
- `feat:` - New features
- `docs:` - Documentation changes
- `test:` - Test additions or modifications
- `refactor:` - Code refactoring
- `chore:` - Maintenance tasks

### Testing Before Commits

**Always run tests before creating commits or PRs**:
```bash
# Activate virtual environment
source venv/bin/activate

# Run full test suite
pytest -v

# Run with coverage
pytest --cov=didlite --cov-report=term-missing
```

**For bug fixes**:
1. Run tests to identify failures
2. Create GitHub issues for bugs found (instead of immediately fixing)
3. Fix bugs and reference issue numbers in commits
4. Verify all tests pass before pushing

### Troubleshooting gh CLI

**If gh can't detect the repository**:
- Ensure you're in the repository directory
- Verify git remote: `git remote -v` (should show `origin` pointing to GitHub)
- Check authentication: `gh auth status`

**If gh commands fail**:
- Re-authenticate: `gh auth logout && gh auth login`
- Verify SSH key is added to GitHub: `gh ssh-key list`
- Test SSH connection: `ssh -T git@github.com`

### Labels and Milestones

**Create labels** (one-time setup):
```bash
# See docs/GH_CLI_SETUP.md for full label creation commands
gh label create "bug" --description "Something isn't working" --color "D73A4A"
gh label create "enhancement" --description "New feature or request" --color "A2EEEF"
# ... (see migration documentation)
```

**Create milestones**:
```bash
gh milestone create "v0.2.0 - Hardening" \
  --description "Security audit preparation and production readiness" \
  --due-date "2025-12-31"
```

## Important Implementation Notes

### Identity Persistence
- **Ephemeral identity:** `AgentIdentity()` with no args generates random identity (lost on restart)
- **Persistent identity:** `AgentIdentity(seed=32_byte_secret)` - same seed always produces same DID
  - Seeds should come from secure storage (env vars, HSM, encrypted files)
  - Never hardcode seeds in source code

### W3C DID:Key Format
The encoding process: `Ed25519 public key → prepend 0xed01 → base58btc encode → prefix "did:key:"`

Example: `did:key:z6MkhaXgBZDvotDkL5257...`
- `z` indicates base58btc encoding (Multibase)
- First decoded bytes `0xed01` indicate Ed25519 key type (Multicodec)
- Remaining 32 bytes are the raw public key

### JWS Token Structure
Standard compact JWS: `base64url(header).base64url(payload).base64url(signature)`
- Header always includes: `{"alg": "EdDSA", "typ": "JWT", "kid": "<signer_did>"}`
- The `kid` field enables self-contained verification (no key distribution infrastructure)

## Use Cases

This library is designed for:
- IoT devices that need self-sovereign identity (sensors, drones, edge gateways)
- AI agents requiring verifiable signatures on actions/messages
- Serverless architectures where devices authenticate without shared secrets
- ARM64 deployments where binary size and dependencies matter
