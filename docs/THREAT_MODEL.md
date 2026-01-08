# Threat Model: didlite

**Version:** 1.0
**Date:** 2025-12-25
**Status:** Phase 2.2 - Security Documentation
**Related:** [SECURITY_AUDIT.md](SECURITY_AUDIT.md), [.github/SECURITY.md](../.github/SECURITY.md)

---

## Executive Summary

This document defines the threat model for **didlite**, a lightweight Python library for generating W3C-compliant Decentralized Identifiers (DIDs) using Ed25519 cryptography. It identifies assets, trust boundaries, threat actors, attack surfaces, and security assumptions to guide secure implementation and usage.

**Target Deployment:** Edge devices, IoT sensors, AI agents, ARM64 platforms (Raspberry Pi, AWS Graviton, M1/M2/M3 Macs)

**Design Philosophy:** "Lite by design" - minimal dependencies, no network calls, cryptographic operations delegated to well-audited libraries (PyNaCl, cryptography)

---

## Table of Contents

1. [Assets](#assets)
2. [Trust Boundaries](#trust-boundaries)
3. [Threat Actors](#threat-actors)
4. [Attack Surfaces](#attack-surfaces)
5. [Threat Scenarios](#threat-scenarios)
6. [Security Assumptions](#security-assumptions)
7. [Out of Scope](#out-of-scope)
8. [Mitigations](#mitigations)
9. [Risk Assessment](#risk-assessment)
10. [References](#references)

---

## Assets

### 1. Private Ed25519 Keys

**Description:** 32-byte Ed25519 private keys (seeds) used for signing operations

**Confidentiality:** CRITICAL
**Integrity:** CRITICAL
**Availability:** HIGH

**Impact of Compromise:**
- **Identity Theft:** Attacker can impersonate the agent/device
- **Signature Forgery:** Attacker can sign malicious JWS tokens on behalf of victim
- **Irrevocable:** `did:key` identifiers are cryptographically bound to keys - no revocation mechanism exists

**Storage Locations:**
- In-memory (during `AgentIdentity` object lifetime)
- Encrypted files (`FileKeyStore` - PBKDF2 + Fernet)
- Environment variables (`EnvKeyStore` - plaintext in process environment)
- External keystores (HSM, cloud KMS - future integration)

---

### 2. Encrypted Seed Files

**Description:** PBKDF2-derived Fernet-encrypted seed files stored by `FileKeyStore`

**Confidentiality:** HIGH
**Integrity:** MEDIUM
**Availability:** MEDIUM

**Impact of Compromise:**
- **Offline Brute-Force:** Attacker with file access can attempt password cracking
  - Mitigated by PBKDF2 (480,000 iterations - exceeds OWASP 2021)
  - Still vulnerable if weak passwords used
- **File Deletion:** Loss of encrypted seeds = permanent identity loss (no recovery)

**Storage Locations:**
- User-specified directories (default: `~/.didlite/keys/`)
- Cloud storage (if user mounts cloud drives)
- Backup systems

---

### 3. JWS Tokens (Signed JWT)

**Description:** Compact JWS tokens created by `create_jws()` containing signed payloads

**Confidentiality:** LOW (payloads are base64-encoded, not encrypted)
**Integrity:** CRITICAL (EdDSA signature protects against tampering)
**Availability:** LOW

**Impact of Compromise:**
- **Replay Attacks:** Intercepted tokens can be reused if no `exp` (expiration) claim
- **Payload Disclosure:** Sensitive data in payload visible to anyone (base64 is encoding, not encryption)
- **Signature Stripping:** If verifier doesn't validate signature, attacker can modify payload

**Transmission Channels:**
- HTTP/HTTPS (if used in web APIs)
- Message queues (MQTT, AMQP for IoT)
- Local inter-process communication
- Log files (if improperly logged)

---

### 4. Decentralized Identifiers (DIDs)

**Description:** Public identifiers in format `did:key:z6Mkh...` derived from public keys

**Confidentiality:** N/A (public by design)
**Integrity:** MEDIUM (tampering detectable via signature verification)
**Availability:** N/A (self-contained, no central registry)

**Impact of Compromise:**
- **DID Spoofing:** Attacker creates similar-looking DID to impersonate (phishing)
- **Correlation:** DIDs are persistent pseudonyms - can be used to track agent activity across contexts

**Storage Locations:**
- Embedded in JWS tokens (`kid` header field)
- Application databases
- Public logs, blockchain records (if published)

---

## Trust Boundaries

### Boundary 1: Python ↔ C (PyNaCl/libsodium)

**Description:** Interface between Python code and PyNaCl's libsodium C library

**Trust Level:** Python code trusts libsodium for cryptographic correctness

**Security Concerns:**
- **Buffer Overflows:** Malformed inputs to PyNaCl could cause memory corruption in libsodium
- **Type Confusion:** Passing non-bytes objects could crash C layer
- **Memory Safety:** Python's garbage collector doesn't control libsodium's memory

**Mitigations (Implemented in Phase 1.1):**
- ✅ Explicit seed validation before PyNaCl calls ([core.py:66-71](../didlite/core.py#L66-L71))
- ✅ Type checks for bytes objects
- ✅ Length validation (exactly 32 bytes for seeds)
- ✅ PyNaCl library maintained by cryptography.io team (well-audited)

**Reference:** [PHASE_1.1_FINDINGS.md](PHASE_1.1_FINDINGS.md) - CRIT-1

---

### Boundary 2: Library ↔ Application Code

**Description:** Public API exposed to library users

**Trust Level:** Library does NOT trust application code to provide valid inputs

**Security Concerns:**
- **Malicious Inputs:** Application may pass malformed DIDs, seeds, JWS tokens
- **Improper Usage:** Application may misuse APIs (e.g., not verifying signatures)
- **Logging Secrets:** Application may log private keys or seeds

**Mitigations:**
- ✅ Comprehensive input validation at all public APIs (Phase 1.1, 1.2)
- ✅ Clear exceptions for invalid inputs (`ValueError`, `BadSignatureError`)
- ✅ Documentation emphasizes security best practices ([.github/SECURITY.md](../.github/SECURITY.md))
- ⚠️ No logging in library (correct design - logging is application responsibility)

**Reference:** [PHASE_1.2_FINDINGS.md](PHASE_1.2_FINDINGS.md)

---

### Boundary 3: Library ↔ File System (FileKeyStore)

**Description:** File I/O for encrypted seed storage

**Trust Level:** Library does NOT trust file system contents

**Security Concerns:**
- **Path Traversal:** Attacker-controlled `identifier` could write to arbitrary paths
- **World-Readable Permissions:** Encrypted files created with insecure permissions
- **Symbolic Link Attacks:** Attacker replaces seed file with symlink to sensitive file

**Mitigations:**
- ✅ Path traversal protection implemented (Issue #10 - resolved in v0.2.0)
- ✅ Uses Python's `open()` - follows symlinks but doesn't create them
- ✅ PBKDF2 + Fernet encryption protects file contents
- ✅ Restrictive file permissions enforced

**Reference:** Issue #10 (resolved)

---

### Boundary 4: Library ↔ Network (JWS Token Transmission)

**Description:** JWS tokens transmitted over network (application-managed)

**Trust Level:** Library assumes network is hostile (tokens can be intercepted/modified)

**Security Concerns:**
- **Eavesdropping:** Tokens transmitted over unencrypted channels reveal payload
- **Man-in-the-Middle:** Attacker modifies token in transit
- **Replay Attacks:** Intercepted tokens reused

**Mitigations:**
- ✅ EdDSA signature prevents tampering (verified by `verify_jws()`)
- ⚠️ No built-in replay protection (application must add `exp`, `jti`, `nonce` claims)
- ⚠️ No encryption (payloads are visible - use HTTPS/TLS at transport layer)

**Application Responsibility:**
- Use HTTPS/TLS for token transmission
- Add expiration (`exp`) claims to JWS payloads
- Implement replay attack detection (nonce tracking, token IDs)

**Reference:** [.github/SECURITY.md](../.github/SECURITY.md) - Known Limitations

---

### Boundary 5: Library ↔ Process Environment (EnvKeyStore)

**Description:** Reading seeds from environment variables

**Trust Level:** Library trusts environment variables are correctly set by operator

**Security Concerns:**
- **Process Dumping:** Environment variables visible in `/proc/<pid>/environ` on Linux
- **Subprocess Inheritance:** Child processes inherit environment (seed leakage)
- **Logging Exposure:** Shell history, CI/CD logs may capture env vars

**Mitigations:**
- ✅ Seeds stored as base64 strings (not raw bytes in env)
- ⚠️ No protection against process dumps (OS-level security required)
- ✅ EnvKeyStore error messages sanitized (Issue #16 - resolved in v0.2.0)

**Best Practices for Users:**
- Use secret management systems (HashiCorp Vault, AWS Secrets Manager)
- Avoid echoing seeds in shell commands
- Clear sensitive env vars after process startup
- Use encrypted environment files (`.env.encrypted`)

**Reference:** Issue #16 (resolved)

---

## Threat Actors

### 1. Network Attacker (Remote, Unauthenticated)

**Capabilities:**
- Intercepts JWS tokens over network (passive eavesdropping)
- Modifies JWS tokens in transit (active MITM)
- Replays intercepted tokens
- Sends malformed tokens to trigger DoS

**Goals:**
- Impersonate legitimate agents
- Forge signed messages
- Disrupt service availability

**Attack Vectors:**
- Unencrypted HTTP transmission
- DNS spoofing / ARP poisoning
- Malicious Wi-Fi access points (common in IoT deployments)

**Mitigations:**
- ✅ Signature verification prevents forgery (`verify_jws()`)
- ⚠️ Application must use HTTPS/TLS for transport encryption
- ⚠️ Application must implement replay protection (expiration, nonces)

---

### 2. Malicious Application Developer (Local, Authenticated)

**Capabilities:**
- Calls library APIs with malicious inputs
- Accesses private keys in memory (if running in same process)
- Logs sensitive data
- Misuses cryptographic APIs

**Goals:**
- Extract private keys from library
- Bypass signature verification
- Cause crashes or undefined behavior

**Attack Vectors:**
- Buffer overflow attempts via oversized inputs
- Type confusion (passing non-bytes to crypto functions)
- Algorithm confusion (if library supported multiple algorithms)
- Improper exception handling

**Mitigations:**
- ✅ Comprehensive input validation (Phase 1.1, 1.2)
- ✅ No algorithm negotiation (EdDSA only, no algorithm confusion)
- ✅ Clear documentation of secure usage patterns
- ✅ Type hints and runtime checks

**Reference:** [PHASE_1.2_FINDINGS.md](PHASE_1.2_FINDINGS.md)

---

### 3. File System Attacker (Local, Low-Privilege)

**Capabilities:**
- Reads encrypted seed files from disk
- Attempts brute-force password cracking (offline)
- Monitors file system for new seed files
- Symlink attacks to redirect file writes

**Goals:**
- Recover private keys via password cracking
- Steal identity by copying seed files
- Cause DoS by corrupting/deleting seed files

**Attack Vectors:**
- World-readable file permissions
- Weak FileKeyStore passwords
- Path traversal vulnerabilities
- Symlink race conditions

**Mitigations:**
- ✅ PBKDF2 key derivation (480,000 iterations) slows brute-force
- ✅ Fernet authenticated encryption (HMAC protects integrity)
- ⚠️ Weak path traversal protection (Issue #10 - MED-2)
- ❌ No explicit file permission setting (OS umask-dependent)

**Best Practices for Users:**
- Use strong FileKeyStore passwords (20+ characters, random)
- Store seed files on encrypted volumes
- Set restrictive directory permissions manually (`chmod 700`)
- Use HSMs for production keys (future feature)

**Reference:** Issue #10 (resolved)

---

### 4. Memory Attacker (Local, High-Privilege)

**Capabilities:**
- Dumps process memory (e.g., `/proc/<pid>/mem`, `gcore`)
- Searches memory for private keys
- Injects code into running process (debugger)

**Goals:**
- Extract private keys from memory
- Modify JWS verification logic to accept forged tokens

**Attack Vectors:**
- Host compromise (root access)
- Container escape (in Docker/Kubernetes)
- VM escape (in cloud environments)
- Kernel exploits

**Mitigations:**
- ❌ No memory scrubbing (private keys remain in Python heap)
- ❌ No memory locking (keys pageable to swap)
- ⚠️ PyNaCl may use secure memory (libsodium's `sodium_mlock()`) but not guaranteed in Python wrapper

**Inherent Limitations:**
- Python is not designed for memory-safe secrets handling
- Garbage collector prevents deterministic key erasure
- Future: Consider HSM integration for high-security deployments

**Out of Scope:**
- Defending against root/kernel-level attackers (OS security responsibility)
- Memory encryption (requires hardware support like Intel SGX)

---

### 5. Timing Attack Adversary (Remote, High-Precision Measurement)

**Capabilities:**
- Measures response times of signature verification
- Uses statistical analysis to infer secret key bits
- Requires thousands to millions of measurements

**Goals:**
- Extract private keys via timing side-channels
- Recover secrets from conditional branches

**Attack Vectors:**
- Remote timing attacks over LAN (microsecond precision)
- Cache-timing attacks (if co-located on shared CPU)
- Power analysis (if physical access to device)

**Mitigations:**
- ✅ **EXCELLENT:** All cryptographic operations use constant-time code
  - PyNaCl's Ed25519 signature verification (libsodium)
  - Fernet's HMAC verification (cryptography library)
  - No conditional branches on secret data in didlite code
- ✅ No password comparison in didlite (Fernet handles this internally)

**Verified in Phase 1.3:**
- No timing vulnerabilities found
- "Security by delegation" - timing safety inherited from libraries

**Reference:** [PHASE_1.3_FINDINGS.md](PHASE_1.3_FINDINGS.md)

---

## Attack Surfaces

### Surface 1: DID Resolution (`resolve_did_to_key()`)

**Entry Point:** `didlite.core.resolve_did_to_key(did: str) -> VerifyKey`

**Inputs:**
- Arbitrary strings (claimed to be DIDs)

**Attack Vectors:**
- **Malformed DIDs:** `did:`, `did:key:`, `did:web:example.com` (wrong method)
- **Invalid Base58:** Characters outside base58 alphabet, invalid multibase prefix
- **Wrong Multicodec:** Non-0xed01 prefix (e.g., secp256k1 keys)
- **Truncated Keys:** Fewer than 32 bytes after decoding
- **Oversized Inputs:** 1MB+ strings to cause memory exhaustion

**Impact:**
- DoS (crashes, hangs)
- Algorithm confusion (accepting non-Ed25519 keys)

**Mitigations (Phase 1.1):**
- ✅ DID format validation (must start with `did:key:z`)
- ✅ Multicodec prefix check (must be 0xed01)
- ✅ Decoded length validation (must be 34 bytes: 2-byte prefix + 32-byte key)
- ✅ Comprehensive error handling (raises `ValueError` on any invalid input)

**Test Coverage:**
- ✅ 27 security tests added in Phase 1.1
- ✅ Fuzzing recommended in Phase 3 (Hypothesis property-based testing)

**Reference:** [PHASE_1.1_FINDINGS.md](PHASE_1.1_FINDINGS.md) - CRIT-2, CRIT-3, CRIT-4

---

### Surface 2: JWS Verification (`verify_jws()`)

**Entry Point:** `didlite.jws.verify_jws(token: str) -> dict`

**Inputs:**
- Arbitrary strings (claimed to be JWS tokens)

**Attack Vectors:**
- **Malformed Tokens:** Missing dots (only 1-2 segments), empty segments
- **Invalid Base64:** Non-base64 characters, incorrect padding
- **Malformed JSON:** Invalid JSON in header/payload
- **Algorithm Confusion:** `{"alg": "none"}` header (if not validated)
- **DID Manipulation:** Invalid DID in `kid` header
- **Signature Stripping:** Replacing signature with empty string

**Impact:**
- Signature bypass (accepting forged tokens)
- DoS (crashes, JSON parsing errors)
- Information disclosure (exception messages revealing internals)

**Mitigations (Phase 1.1):**
- ✅ Token segment count validation (must be exactly 3 segments)
- ✅ Base64 padding validation (correct padding calculation)
- ✅ JSON parsing error handling
- ✅ Algorithm enforcement (EdDSA only, no negotiation)
- ✅ Signature verification via PyNaCl (constant-time)

**Mitigations Complete:**
- ✅ Exception messages sanitized (Issue #11 - resolved in v0.2.0)

**Test Coverage:**
- ✅ Segment validation tests
- ✅ Invalid signature rejection tests
- ⏳ Fuzzing recommended (Phase 3)

**Reference:** [PHASE_1.1_FINDINGS.md](PHASE_1.1_FINDINGS.md) - HIGH-1, HIGH-2

---

### Surface 3: Seed Import (`AgentIdentity(seed=...)`)

**Entry Point:** `didlite.core.AgentIdentity.__init__(seed: bytes)`

**Inputs:**
- User-provided bytes objects (claimed to be 32-byte seeds)

**Attack Vectors:**
- **Wrong Type:** Non-bytes objects (strings, integers, lists)
- **Wrong Size:** 0 bytes, 31 bytes, 33 bytes, 1MB+
- **Untrusted Source:** Seeds from network, user input, files

**Impact:**
- Crashes in PyNaCl (buffer overflow, type confusion)
- Weak keys (if non-random seeds accepted)

**Mitigations (Phase 1.1):**
- ✅ Type validation (`isinstance(seed, bytes)`)
- ✅ Length validation (`len(seed) == 32`)
- ✅ Validation before PyNaCl call (protects C boundary)

**Test Coverage:**
- ✅ Seed size validation tests
- ✅ Type error tests

**Reference:** [PHASE_1.1_FINDINGS.md](PHASE_1.1_FINDINGS.md) - CRIT-1

---

### Surface 4: FileKeyStore Operations

**Entry Points:**
- `FileKeyStore.save_seed(identifier: str, seed: bytes)`
- `FileKeyStore.load_seed(identifier: str) -> bytes`
- `FileKeyStore.get_or_create_identity(identifier: str) -> AgentIdentity`

**Inputs:**
- `identifier`: User-controlled strings (may contain path traversal sequences)
- `seed`: User-provided seeds
- `password`: User-provided encryption passwords

**Attack Vectors:**
- **Path Traversal:** `identifier = "../../etc/passwd"` to overwrite system files
- **Symlink Attacks:** Replace seed file with symlink to sensitive file
- **Weak Passwords:** Brute-forceable PBKDF2 encryption
- **File Permission Issues:** World-readable seed files

**Impact:**
- Arbitrary file write/read
- Private key theft (offline brute-force)
- DoS (file corruption, disk exhaustion)

**Mitigations:**
- ✅ Path traversal protection implemented (Issue #10 - resolved in v0.2.0)
- ✅ PBKDF2 (480,000 iterations) for key derivation
- ✅ Fernet authenticated encryption (HMAC integrity)
- ✅ Explicit file permission setting enforced

**Best Practices for Users:**
- Use strong passwords (20+ characters)
- Restrict keystore directory permissions (`chmod 700`)
- Store keystores on encrypted volumes

**Reference:** Issue #10 (resolved)

---

### Surface 5: JWK/PEM Import (`from_jwk()`, `from_pem()`)

**Entry Points:**
- `AgentIdentity.from_jwk(jwk_dict: dict) -> AgentIdentity`
- `AgentIdentity.from_pem(pem_bytes: bytes) -> AgentIdentity`

**Inputs:**
- Arbitrary dictionaries (JWK format)
- Arbitrary bytes (PEM format)

**Attack Vectors:**
- **Type Confusion:** Non-dict for JWK, non-bytes for PEM
- **Malformed JWK:** Missing fields, wrong key type (`kty: "RSA"`)
- **Malformed PEM:** Invalid base64, wrong algorithm
- **Wrong Key Size:** Non-32-byte keys after decoding

**Impact:**
- Crashes (type errors, decoding errors)
- Information disclosure (exception messages)

**Mitigations:**
- ✅ JWK format validation (checks `kty`, `crv` fields)
- ✅ PEM algorithm validation (checks for Ed25519)
- ✅ Type validation implemented (Issues #12, #13 - resolved in v0.2.0)
- ✅ PEM error messages sanitized (Issue #14 - resolved in v0.2.0)

**Test Coverage:**
- ✅ Format validation tests
- ✅ Type validation tests (added in v0.2.0)

**Reference:** Issues #12-14 (resolved)

---

## Threat Scenarios

### Scenario 1: IoT Device Key Theft via Weak Password

**Attacker:** File System Attacker (low-privilege local access)

**Attack Steps:**
1. Attacker gains read access to IoT device file system (e.g., via SSH with stolen credentials)
2. Copies encrypted seed file from `~/.didlite/keys/device-001.seed`
3. Runs offline password cracking (dictionary attack, GPU-accelerated)
4. Recovers weak password (`Password123!`) after 2 hours
5. Decrypts seed using Fernet with PBKDF2-derived key
6. Imports seed into own `AgentIdentity` instance
7. Creates forged JWS tokens signed with stolen identity

**Impact:**
- Complete identity compromise
- Attacker can impersonate device indefinitely (no revocation)
- Forged sensor data, malicious commands

**Likelihood:** MEDIUM (requires file access + weak password)

**Mitigations:**
- ✅ PBKDF2 slows brute-force (480,000 iterations ≈ 0.5-1 second per password)
- ⚠️ User education required (strong password enforcement)
- 🔮 Future: HSM integration eliminates file-based storage

**Risk Rating:** MEDIUM (Impact: CRITICAL, Likelihood: MEDIUM)

---

### Scenario 2: JWS Replay Attack in Smart Home

**Attacker:** Network Attacker (passive eavesdropping)

**Attack Steps:**
1. User's smart home hub sends JWS token over HTTP to unlock door:
   ```json
   {"action": "unlock", "door": "front", "timestamp": 1703001234}
   ```
2. Attacker intercepts token via Wi-Fi packet sniffing
3. Signature verification passes (token is legitimate)
4. 1 hour later, attacker replays same token
5. Door unlocks again (no expiration check)

**Impact:**
- Unauthorized access to physical location
- Replay attacks work indefinitely (no token expiration)

**Likelihood:** HIGH (if application doesn't implement replay protection)

**Mitigations:**
- ⚠️ **Application Responsibility:** Must add `exp` (expiration) claim
- ⚠️ **Application Responsibility:** Must track used tokens (nonce/JTI)
- ✅ Use HTTPS/TLS to prevent eavesdropping (best practice)

**Risk Rating:** HIGH (Impact: HIGH, Likelihood: HIGH without app-layer mitigations)

**Reference:** [.github/SECURITY.md](../.github/SECURITY.md) - Known Limitations #4

---

### Scenario 3: Path Traversal in Multi-Tenant Environment

**Attacker:** Malicious Application Developer

**Attack Steps:**
1. Attacker controls `identifier` parameter in multi-tenant system
2. Creates identity with malicious identifier:
   ```python
   store = FileKeyStore("/app/tenant_keys", password="system_pw")
   store.save_seed("../../../../etc/cron.d/backdoor", malicious_seed)
   ```
3. Path traversal bypasses weak validation
4. Writes encrypted seed to `/etc/cron.d/backdoor`
5. If seed file is valid cron syntax (unlikely but possible), achieves code execution

**Impact:**
- Previously: Arbitrary file write vulnerability
- Now: PREVENTED by path traversal protection

**Likelihood:** N/A (ELIMINATED in v0.2.0)

**Mitigations:**
- ✅ Path traversal protection implemented (Issue #10 - resolved in v0.2.0)
- ✅ Identifier validation enforced

**Risk Rating:** MEDIUM (Impact: HIGH, Likelihood: LOW)

**Reference:** Issue #10 (resolved)

---

### Scenario 4: Algorithm Confusion Attack (PREVENTED)

**Attacker:** Network Attacker (active MITM)

**Attack Steps:**
1. Attacker intercepts JWS token signed with EdDSA
2. Modifies header to use HMAC-SHA256 (symmetric algorithm):
   ```json
   {"alg": "HS256", "typ": "JWT", "kid": "did:key:z6Mkh..."}
   ```
3. Extracts public key from DID in `kid` header
4. Uses public key as HMAC secret (known to attacker, since it's public)
5. Computes HMAC signature with public key
6. Verifier uses public key as HMAC secret (if algorithm not validated)
7. Signature verification passes (HMAC matches)

**Impact:**
- Complete signature bypass
- Attacker can forge arbitrary tokens

**Likelihood:** N/A (PREVENTED by didlite design)

**Mitigations:**
- ✅ **didlite only supports EdDSA** - no algorithm negotiation
- ✅ No algorithm parameter in `verify_jws()` - hardcoded to EdDSA
- ✅ Header `alg` field ignored (algorithm is implicit)

**Risk Rating:** N/A (ELIMINATED by design)

**Design Decision:** This is why didlite is "lite" - supporting multiple algorithms would introduce complexity and attack surface.

---

### Scenario 5: Memory Dump Key Extraction (Out of Scope)

**Attacker:** Memory Attacker (root access)

**Attack Steps:**
1. Attacker gains root access to server (via kernel exploit)
2. Dumps process memory: `gcore <pid>`
3. Searches memory dump for Ed25519 private key patterns:
   ```bash
   strings core.<pid> | grep -P '[0-9a-f]{64}'
   ```
4. Finds 32-byte seed in Python heap
5. Imports seed into own `AgentIdentity`

**Impact:**
- Complete identity compromise
- Attacker controls agent identity

**Likelihood:** HIGH (if attacker has root access)

**Mitigations:**
- ❌ **Out of Scope:** didlite cannot defend against root-level attackers
- ❌ No memory locking (Python's `mlock()` unreliable)
- ❌ No memory scrubbing (garbage collector prevents deterministic erasure)

**Risk Rating:** N/A (Out of Scope)

**Recommendation:** Use HSMs for production deployments requiring defense against host compromise

---

## Security Assumptions

### 1. PyNaCl and libsodium are Correct

**Assumption:** PyNaCl's Ed25519 implementation (via libsodium) is cryptographically secure and free of critical vulnerabilities.

**Justification:**
- libsodium is widely audited (used by Signal, Tor, Wireguard)
- PyNaCl maintained by cryptography.io (reputable security team)
- Ed25519 is NIST-approved (FIPS 186-5)

**If Violated:**
- All signatures are potentially forgeable
- Private key recovery may be possible

**Risk Mitigation:**
- Monitor PyNaCl security advisories
- Use `pip-audit` for dependency vulnerability scanning (Phase 4)

---

### 2. Python Standard Library is Secure

**Assumption:** Python's `base64`, `json`, `os`, `hashlib` modules are free of critical vulnerabilities.

**Justification:**
- Python core maintained by PSF (Python Software Foundation)
- Extensive fuzzing and testing of standard library
- Security patches released regularly

**If Violated:**
- Parsing vulnerabilities (JSON, base64) could allow DoS or RCE
- File system operations could be exploited

**Risk Mitigation:**
- Use latest Python version (3.8+)
- Monitor Python security advisories (CVEs)

---

### 3. Operating System Provides Secure Randomness

**Assumption:** `SigningKey.generate()` uses cryptographically secure random number generator (CSPRNG).

**Justification:**
- PyNaCl uses `os.urandom()` internally
- `os.urandom()` uses `/dev/urandom` on Linux, `CryptGenRandom` on Windows
- Modern OS kernels seed RNGs from hardware entropy sources

**If Violated:**
- Predictable private keys (attacker can guess keys)
- Collision attacks (multiple devices generate same key)

**Risk Mitigation:**
- Ensure OS is properly configured (entropy sources enabled)
- For embedded devices, verify `/dev/random` is seeded at boot
- Consider hardware RNGs (TPM, TRNG) for high-security deployments

---

### 4. File System Permissions are Properly Configured

**Assumption:** Encrypted seed files are stored in directories with restrictive permissions (e.g., `chmod 700`).

**Justification:**
- UNIX permission model prevents unauthorized file access
- User is responsible for configuring keystore directory

**If Violated:**
- World-readable seed files allow offline brute-force attacks

**Risk Mitigation:**
- Document best practices in SECURITY.md ✅ (done)
- Consider setting file permissions explicitly in future versions
- Warn users if directory permissions are too permissive (future enhancement)

---

### 5. Passwords Used with FileKeyStore are Strong

**Assumption:** Users choose strong passwords (20+ characters, random, from password manager).

**Justification:**
- PBKDF2 (480,000 iterations) makes brute-force expensive
- Assumes users follow security best practices

**If Violated:**
- Weak passwords allow offline password cracking
- Encrypted seeds become trivially recoverable

**Risk Mitigation:**
- Document password requirements in SECURITY.md ✅ (done)
- Consider password strength validation in `FileKeyStore.__init__()` (future enhancement)
- Recommend passphrase generators (diceware)

---

### 6. Applications Verify JWS Signatures

**Assumption:** Applications using didlite call `verify_jws()` before trusting token payloads.

**Justification:**
- Library provides signature verification function
- Documentation emphasizes verification requirement

**If Violated:**
- Applications accept forged tokens
- Signature protection bypassed entirely

**Risk Mitigation:**
- Prominent documentation warnings ✅ (in SECURITY.md)
- Consider API design that makes verification mandatory (future: return `VerifiedPayload` type)
- Example code always shows verification pattern

---

### 7. Applications Implement Replay Protection

**Assumption:** Applications add expiration (`exp`), nonce (`jti`), or timestamp validation to prevent replay attacks.

**Justification:**
- JWS standard supports these claims (RFC 7519)
- Replay protection is application-layer concern, not library concern

**If Violated:**
- Intercepted tokens can be reused indefinitely
- Attacker can replay old commands

**Risk Mitigation:**
- Document replay attack risk in SECURITY.md ✅ (done)
- Provide example code with `exp` claim (in future documentation)
- Consider adding `create_jws_with_expiration()` helper function

---

### 8. Network Transport Uses TLS/HTTPS

**Assumption:** JWS tokens transmitted over encrypted channels (HTTPS, TLS, Noise Protocol).

**Justification:**
- JWS payloads are base64-encoded, not encrypted
- Signature protects integrity, not confidentiality

**If Violated:**
- Payload contents visible to eavesdroppers
- Sensitive data exposed

**Risk Mitigation:**
- Document in SECURITY.md ✅ (done)
- Warn users that JWS is not encryption
- Consider adding JWE (JSON Web Encryption) support in future (post-v1.0)

---

## Out of Scope

The following threats are explicitly **out of scope** for didlite's threat model:

### 1. Host/OS Compromise (Root/Kernel Access)

**Rationale:** No userspace library can defend against attackers with kernel-level privileges.

**Application Responsibility:** Use OS security features (SELinux, AppArmor), secure boot, TPMs.

---

### 2. Side-Channel Attacks (Power Analysis, EM Leaks)

**Rationale:** Physical side-channels require hardware-level mitigations (constant-power gates, EM shielding).

**Application Responsibility:** Use tamper-resistant hardware (HSMs, secure elements) for high-security deployments.

---

### 3. Blockchain/Ledger Attacks

**Rationale:** didlite uses `did:key` (self-contained), not blockchain-based DID methods (`did:ethr`, `did:ion`).

**Application Responsibility:** If using blockchain DIDs, implement separate security measures.

---

### 4. Social Engineering / Phishing

**Rationale:** Library cannot prevent users from sharing private keys or being tricked into running malicious code.

**Application Responsibility:** User education, phishing-resistant authentication (WebAuthn).

---

### 5. Denial of Service (Resource Exhaustion)

**Rationale:** DoS attacks are application/infrastructure concern (rate limiting, resource quotas).

**Application Responsibility:** Implement request throttling, circuit breakers, resource limits.

**Note:** Library includes input size validation to prevent trivial DoS (e.g., 1MB DIDs), but cannot prevent all resource exhaustion attacks.

---

### 6. Quantum Computing Attacks

**Rationale:** Ed25519 is not post-quantum secure. Quantum computers with sufficient qubits (future threat) can break ECDLP.

**Timeline:** NIST estimates quantum threat to ECDSA/EdDSA by 2030-2040.

**Mitigation Path:**
- Monitor NIST post-quantum cryptography standardization (FIPS 203/204/205)
- Plan migration to post-quantum signatures (CRYSTALS-Dilithium, Falcon) in didlite v2.0 (post-2030)

---

### 7. Key Revocation / Identity Recovery

**Rationale:** `did:key` identifiers are immutable - no revocation or key rotation mechanism exists by design.

**Application Responsibility:**
- Use short-lived credentials (rotate DIDs periodically)
- Implement identity recovery at application layer (multi-key schemes, social recovery)

**Future Work:** Consider `did:web` or `did:ion` support for revocable identities (post-v1.0).

---

## Mitigations

### Implemented Mitigations (v0.2.0)

| Threat | Mitigation | Status | Reference |
|--------|-----------|--------|-----------|
| Buffer overflows at PyNaCl boundary | Seed validation before C calls | ✅ DONE | Phase 1.1, CRIT-1 |
| DID parsing crashes | Comprehensive DID format validation | ✅ DONE | Phase 1.1, CRIT-2/3/4 |
| JWS token forgery | Segment count + signature validation | ✅ DONE | Phase 1.1, HIGH-1/2 |
| Algorithm confusion | EdDSA-only design (no negotiation) | ✅ DONE | Design |
| Timing attacks on signatures | Constant-time PyNaCl operations | ✅ DONE | Phase 1.3 |
| File storage brute-force | PBKDF2 (480k iterations) + Fernet | ✅ DONE | Existing |

### Completed Mitigations (v0.2.0)

| Threat | Mitigation | Status | Reference |
|--------|-----------|--------|-----------|
| Path traversal in FileKeyStore | Implemented `os.path.basename()` | ✅ DONE | Issue #10 |
| Error message information leakage | Sanitized exception messages | ✅ DONE | Issues #11-16 |
| Type confusion in JWK/PEM | Added runtime type checks | ✅ DONE | Issues #12-13 |

### Application-Layer Mitigations (User Responsibility)

| Threat | Mitigation | Documentation |
|--------|-----------|---------------|
| Replay attacks | Add `exp`, `jti`, `nonce` claims | ✅ SECURITY.md |
| Eavesdropping | Use HTTPS/TLS transport | ✅ SECURITY.md |
| Weak passwords | Use strong passwords (20+ chars) | ✅ SECURITY.md |
| Host compromise | Use HSMs, encrypted volumes | ✅ SECURITY.md |
| File permissions | Set `chmod 700` on keystore dirs | ✅ SECURITY.md |

---

## Risk Assessment

### Critical Risks (ELIMINATED in Phase 1.1)

| Risk | Severity | Likelihood | Status |
|------|----------|-----------|--------|
| Memory corruption at PyNaCl boundary | CRITICAL | MEDIUM | ✅ FIXED (seed validation) |
| DID parser crashes | CRITICAL | HIGH | ✅ FIXED (format validation) |
| JWS signature bypass | CRITICAL | MEDIUM | ✅ FIXED (segment validation) |
| Algorithm confusion | CRITICAL | LOW | ✅ PREVENTED (design) |

### High Risks (Mitigated or Deferred)

| Risk | Severity | Likelihood | Mitigation | Status |
|------|----------|-----------|-----------|--------|
| Replay attacks | HIGH | HIGH | Application adds `exp` claims | ⚠️ USER RESPONSIBILITY |
| Weak password brute-force | HIGH | MEDIUM | PBKDF2 + strong password policy | ⚠️ USER RESPONSIBILITY |
| Network eavesdropping | HIGH | MEDIUM | Use HTTPS/TLS | ⚠️ USER RESPONSIBILITY |

### Medium Risks (RESOLVED in v0.2.0)

| Risk | Severity | Likelihood | Mitigation | Status |
|------|----------|-----------|-----------|--------|
| Path traversal | MEDIUM | LOW | Use `basename()` | ✅ RESOLVED (Issue #10) |
| Information disclosure | MEDIUM | LOW | Sanitize errors | ✅ RESOLVED (Issues #11-16) |

### Low Risks (Accepted)

| Risk | Severity | Likelihood | Justification |
|------|----------|-----------|---------------|
| Memory dumps | HIGH | LOW | Out of scope (requires root access) |
| Physical side-channels | MEDIUM | LOW | Out of scope (requires hardware mitigations) |
| Quantum computing | HIGH | VERY LOW | Future threat (post-2030) |

---

## References

### Internal Documentation

- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) - Security audit preparation checklist
- [.github/SECURITY.md](../.github/SECURITY.md) - Vulnerability disclosure policy
- [PHASE_1.1_FINDINGS.md](PHASE_1.1_FINDINGS.md) - Cryptographic implementation review
- [PHASE_1.2_FINDINGS.md](PHASE_1.2_FINDINGS.md) - Input validation review
- [PHASE_1.3_FINDINGS.md](PHASE_1.3_FINDINGS.md) - Timing attack analysis
- [PHASE_1.4_FINDINGS.md](PHASE_1.4_FINDINGS.md) - Error handling review
- [PHASE_1_SUMMARY.md](PHASE_1_SUMMARY.md) - Phase 1 complete summary

### External Standards

- [W3C DID Core Specification](https://www.w3.org/TR/did-core/) - DID format and resolution
- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515) - JWS token format
- [RFC 8032 - Edwards-Curve Digital Signature Algorithm](https://tools.ietf.org/html/rfc8032) - Ed25519 specification
- [NIST SP 800-186 - Digital Signature Standard](https://csrc.nist.gov/publications/detail/sp/800-186/final) - Ed25519 approval

### Security Resources

- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [Microsoft STRIDE Methodology](https://learn.microsoft.com/en-us/security/engineering/stride-threat-model)
- [NIST SP 800-154 - Guide to Data-Centric System Threat Modeling](https://csrc.nist.gov/publications/detail/sp/800-154/draft)

---

**Document Status:** ✅ COMPLETE
**Last Updated:** 2025-12-25
**Next Review:** Before v1.0.0 release or after Phase 3 (Security Testing)

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
