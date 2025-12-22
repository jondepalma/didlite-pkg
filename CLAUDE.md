# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`didlite` is a zero-dependency-bloat Python library for generating W3C Standard Decentralized Identifiers (DIDs) using Ed25519 keys. It targets edge devices, IoT sensors, and AI agents that need cryptographically verifiable identity without requiring central servers, certificate authorities, or blockchains.

**Key Design Principle:** "Lite" by design - only supports `did:key` method to ensure maximum portability for Edge AI and IoT deployments, especially ARM64 devices (Raspberry Pi, AWS Graviton, M1/M2/M3 Macs).

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

For cross-project development (e.g., with orchestrator or agent-sdk):
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

### Dependencies
- `pynacl>=1.5.0` - Ed25519 signing (libsodium wrapper)
- `py-multibase>=1.0.0` - Multibase encoding for DID formatting
- `python-jose[cryptography]>=3.3.0` - Standard JWT handling utilities

Requires Python 3.8+

## Gitea Workflow with Tea CLI

This project uses Gitea for issue tracking and pull requests. The `tea` CLI is configured for seamless workflow.

### Tea CLI Configuration

**Important**: The tea CLI is configured to work with the git remote. The configuration is in `~/.config/tea/config.yml`:
- **URL**: `http://localhost:3000` (requires port-forwarding to K3s Gitea instance)
- **SSH Host**: `gitea` (matches the git remote `git@gitea:jondepalma/didlite-pkg.git`)
- **User**: `jondepalma`

**Prerequisites**:
- Ensure Gitea port-forward is active: `kubectl port-forward -n dev svc/gitea-http 3000:3000`
- The tea CLI auto-detects the repository from git remotes (no need for `-r` flag when in repo directory)

### Issue Management

**Create an issue**:
```bash
tea issues create --title "Issue title" --description "Detailed description of the issue"
```

**List issues**:
```bash
tea issues list              # List open issues
tea issues list --state all  # List all issues (open and closed)
```

**Close an issue**:
```bash
tea issues close <issue_number>
```

**View issue details**:
```bash
tea issues <issue_number>
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
tea pulls create --base main --head dev \
  --title "Brief PR title" \
  --description "## Summary
- What changed
- Why it changed
- Impact

## Test Results
<test output>

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

**List pull requests**:
```bash
tea pulls list
tea pulls list --state all
```

**View PR details**:
```bash
tea pulls <pr_number>
```

### Git Workflow Best Practices

**Branch Strategy**:
- `main`: Production-ready code
- `dev`: Development branch (default for new features/fixes)
- Feature branches: Created from `dev` as needed

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
2. Create Gitea issues for bugs found (instead of immediately fixing)
3. Fix bugs and reference issue numbers in commits
4. Verify all tests pass before pushing

### Troubleshooting Tea CLI

**If tea can't detect the repository**:
- Ensure you're in the repository directory
- Verify git remote matches tea config: `git remote -v`
- Check tea config: `cat ~/.config/tea/config.yml`
- The `ssh_host` in tea config must match the git remote hostname (currently: `gitea`)

**If port-forwarding is not active**:
```bash
# Check for existing port-forward
ps aux | grep "port-forward.*gitea"

# Start port-forward if needed
kubectl port-forward -n dev svc/gitea-http 3000:3000 &
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
