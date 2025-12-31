# didlite 🆔

**Verifiable Identity for Agents, IoT, and Edge Devices.**

`didlite` is a zero-dependency-bloat Python library that generates **W3C Standard Decentralized Identifiers (DIDs)** using `Ed25519` keys.

It allows any Python program (Drone, Sensor, AI Agent) to create a cryptographically verifiable identity and sign data without needing a central server, certificate authority, or blockchain.

---

## ⚡ Why `didlite`?

Most Identity libraries (SSI) are massive. They require Rust compilers, system binaries, or heavy async runtimes.

* **Zero Bloat:** Pure Python wrapper around `pynacl` (libsodium).
* **Standards Compliant:** Produces valid `did:key` identifiers (W3C CCG).
* **Web-Ready:** Signs standard JSON Web Signatures (JWS).
* **ARM64 Native:** Runs seamlessly on Raspberry Pi, AWS Graviton, and M1/M2/M3 Macs.

### The Problem it Solves
**Scenario:** You have 1,000 temperature sensors deployed in the field.
* **The Old Way:** Hardcode a shared API key (Insecure) or manage 1,000 mTLS certificates (Painful).
* **The `didlite` Way:** Each sensor generates its own ID at startup. The server verifies the signature mathematically. No database required.

### Performance Benchmarks (v0.2.3) - 2025-12-30

***Environment: Raspberry Pi 5 8GB***

| Operation | Avg Time | Throughput | Notes |
|-----------|----------|------------|-------|
| Identity Generation | 0.11ms | ~9,200/sec | No overhead from v0.2.3 changes |
| Token Creation | 0.08ms | ~13,100/sec | Includes `iat` timestamp validation |
| Token Verification | 0.24ms | ~4,200/sec | Now returns `(header, payload)` tuple |
| DID Extraction | 0.01ms | ~190,000/sec | **NEW** - Fast header parsing without signature verification |
| Custom Headers | 0.08ms | ~13,000/sec | **NEW** - Zero overhead for custom `typ`, etc. |

**Key Takeaways:**
- ✅ v0.2.3 header enhancements add **negligible overhead** (<0.01ms)
- ✅ `extract_signer_did()` is **~24x faster** than full verification (useful for routing/logging)
- ✅ All operations remain suitable for **high-throughput IoT/edge deployments**
- ✅ Ed25519 + PyNaCl's libsodium wrapper delivers excellent ARM64 performance

---

## 📦 Installation

    pip install didlite

---

## 🚀 Quick Start

### 1. The Agent (Sensor/Device)
The device generates an identity and signs its telemetry data.

    import didlite

    # 1. Generate Identity (Ed25519)
    # In production, pass a 32-byte seed to persist identity across reboots.
    agent = didlite.AgentIdentity() 

    print(f"Device ID: {agent.did}")
    # Output: did:key:z6MkhaXgBZDvotDkL5257...

    # 2. Create a Payload
    telemetry = {
        "temp": 24.5,
        "unit": "C",
        "timestamp": 1678900000
    }

    # 3. Sign the Payload (JWS)
    token = didlite.create_jws(agent, telemetry)
    print(f"Signed Token: {token}")

### 2. The Verifier (Server/Gateway)
The server receives the token. It does **not** need to look up the device in a database. The ID *is* the key.

    import didlite

    token = "eyJhbGciOiJFZERTQ..." # The token from the device

    try:
        # 1. Verify Signature & Integrity
        # If this passes, we KNOW the data came from the DID in the header.
        header, payload = didlite.verify_jws(token)

        print("Valid Data from:", header['kid']) # Signer DID from header
        print("Temperature:", payload['temp'])

    except Exception as e:
        print(f"SECURITY ALERT: Invalid signature! {e}")

---

## 🛠 Advanced Usage

### Persistent Identity (Using Seeds)
If a device reboots, you want it to have the same DID. Use a secure 32-byte seed (e.g., from an environment variable or HSM).

    import os
    from didlite import AgentIdentity

    # Load secret from secure storage
    seed_bytes = os.getenv("DEVICE_SECRET_KEY").encode()[:32]

    agent = AgentIdentity(seed=seed_bytes)

### Resolving DIDs
If you just want to check a DID string and get the raw public key bytes:

    from didlite import resolve_did_to_key

    did = "did:key:z6MkhaXgBZDvotDkL5257..."
    verify_key = resolve_did_to_key(did)

    # Now use verify_key to check raw signatures

---

## 🧪 Testing & Quality

### Test Coverage (v0.2.3)

**Coverage by Module:**

| Module | Coverage | Status |
|--------|----------|--------|
| `didlite/core.py` | **98%** | ✅ All security-critical paths tested |
| `didlite/jws.py` | **99%** | ✅ Algorithm confusion attacks prevented |
| `didlite/keystore.py` | **95%** | ✅ All storage backends validated |
| **Overall** | **97.2%** | ✅ Production-ready (321 statements, 312 covered) |

**Test Suite Breakdown:**

| Test Category | Tests | Description |
|--------------|-------|-------------|
| **Compliance** (`test_compliance.py`) | 18 | W3C DID & RFC 7515/7519 JWT/JWS standards |
| **Core** (`test_core.py`) | 37 | Identity, DID resolution, JWK/PEM export |
| **Fuzzing** (`test_fuzzing.py`) | 32 | Malformed inputs, attack scenarios, DoS prevention |
| **Integration** (`test_integration.py`) | 5 | Cross-library compatibility (authlib) |
| **JWS** (`test_jws.py`) | 63 | Token creation/verification, headers, expiration |
| **Keystore** (`test_keystore.py`) | 49 | Storage backends, encryption, persistence |
| **Security** (`test_security.py`) | 32 | Error sanitization, input validation |
| **Total** | **236** | **233 passed, 3 skipped** |

**What's Tested:**
- ✅ W3C DID:key compliance (RFC 8032, Multicodec 0xed01, base58btc encoding)
- ✅ JWS/JWT standards (RFC 7515, RFC 7519, EdDSA signatures)
- ✅ Attack prevention (algorithm confusion, signature tampering, token replay, missing 'kid')
- ✅ Keystore security (PBKDF2 encryption, file permissions 0o600, path traversal)
- ✅ Cross-library compatibility (authlib JWS/JWK interop)
- ✅ Edge cases (malformed tokens, corrupted data, expired tokens, future-dated tokens)

Run tests: `pytest --cov=didlite --cov-report=term-missing`
See [docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md) for detailed testing documentation.

---

## 🤝 Contributing
We keep this library "lite" on purpose. We only support `did:key` to ensure maximum portability for Edge AI and IoT.

## 📄 License
Apache 2.0 - Commercial use allowed.
