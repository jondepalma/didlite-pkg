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
- `python-multibase>=1.0.3` - Multibase encoding for DID formatting
- `python-jose[cryptography]>=3.3.0` - Standard JWT handling utilities

Requires Python 3.8+

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
