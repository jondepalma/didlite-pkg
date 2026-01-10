# didlite 🆔

![Beta](https://img.shields.io/badge/status-beta-yellow) ![Python](https://img.shields.io/badge/python-3.9+-blue.svg) ![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)

> ⚠️ **BETA STATUS - SECURITY AUDIT PENDING**
>
> This library is in active development and **has not undergone an independent security audit**.
> While we've conducted comprehensive internal security hardening with [23+ security fixes](https://github.com/jondepalma/didlite-pkg/issues?q=is%3Aissue+is%3Aclosed+label%3Asecurity),
> we recommend **against production use** until an external audit is complete.
>
> **Use at your own risk.** See [SECURITY.md](.github/SECURITY.md) for vulnerability reporting.

---

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

**Scenario 1: AI Agents** - You deploy autonomous agents that need to communicate and transact with each other.
* **The Old Way:** Central API keys (shared secrets = single point of failure) or OAuth servers (requires infrastructure).
* **The `didlite` Way:** Each agent generates its own identity. Messages are cryptographically signed. Trust is mathematical, not infrastructural.

**Scenario 2: IoT at Scale** - You have 1,000 temperature sensors deployed in the field.
* **The Old Way:** Hardcode a shared API key (insecure) or manage 1,000 mTLS certificates (painful).
* **The `didlite` Way:** Each sensor generates its own ID at startup. The server verifies the signature mathematically. No database required.

### How It Works: Trust Architecture

```mermaid
sequenceDiagram
    participant Agent as AI Agent / IoT Device
    participant Verifier as Server / Gateway

    Note over Agent: Generate Identity
    Agent->>Agent: identity = AgentIdentity()
    Agent->>Agent: did = "did:key:z6Mkh..."

    Note over Agent: Sign Message
    Agent->>Agent: token = create_jws(identity, payload)

    Agent->>Verifier: Send signed token

    Note over Verifier: Verify Signature
    Verifier->>Verifier: header, payload = verify_jws(token)
    Verifier->>Verifier: Extract DID from header['kid']
    Verifier->>Verifier: Resolve DID → public key
    Verifier->>Verifier: Verify signature with public key

    alt Signature Valid
        Verifier->>Agent: ✅ Trust established
        Note over Verifier: No database lookup needed<br/>DID IS the public key
    else Signature Invalid
        Verifier->>Agent: ❌ Reject (tampering detected)
    end
```

**Key Insight:** The DID itself encodes the public key (via Multicodec + Multibase). No PKI infrastructure, no certificate authorities, no centralized identity servers.

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

```bash
pip install didlite
```

**Note:** didlite is currently in beta (v0.2.5). Breaking changes may occur before v1.0.0.

---

## 🚀 Quick Start

[didlite-examples](https://github.com/jondepalma/didlite-examples) - Visit the companion repository for complete example code.

### Example 1: AI Agent Communication

**Agent 1 (Research Agent)** - Collects and signs lead data:

```python
import didlite

# Agent generates its own identity
research_agent = didlite.AgentIdentity()
print(f"Research Agent DID: {research_agent.did}")

# Create a signed lead record
lead_data = {
    "action": "lead_discovered",
    "company": "Acme Corp",
    "industry": "manufacturing",
    "interest": "IoT sensors",
    "source": "web_research"
}

# Sign the lead data
signed_lead = didlite.create_jws(research_agent, lead_data)
# Now send signed_lead to CRM agent...
```

**Agent 2 (CRM Agent)** - Verifies and processes:

```python
import didlite

# Receive signed lead from research agent
# signed_lead = "eyJhbGciOiJFZERTQ..."

try:
    # Verify the signature
    header, payload = didlite.verify_jws(signed_lead)

    # Extract the signer's DID
    signer_did = header['kid']

    print(f"✅ Verified lead from: {signer_did}")
    print(f"Company: {payload['company']}")
    print(f"Interest: {payload['interest']}")

    # Add to CRM database with attribution to research_agent...

except Exception as e:
    print(f"❌ Invalid signature - rejecting lead: {e}")
```

### Example 2: IoT Sensor Data

**The Sensor** - Generates identity and signs telemetry:

```python
import didlite

# In production, load seed from secure storage
sensor = didlite.AgentIdentity()

# Sign telemetry data
telemetry = {
    "temp": 24.5,
    "unit": "C",
    "timestamp": 1678900000
}

token = didlite.create_jws(sensor, telemetry)
# Send token to gateway...
```

**The Gateway** - Verifies without database lookup:

```python
import didlite

# token = "eyJhbGciOiJFZERTQ..." # Received from sensor

try:
    header, payload = didlite.verify_jws(token)

    print(f"Valid data from: {header['kid']}")
    print(f"Temperature: {payload['temp']}°{payload['unit']}")

except Exception as e:
    print(f"SECURITY ALERT: Invalid signature! {e}")
```

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

## 🤝 Getting Help

### Community Support (Free)

- **📖 Documentation**: [Documentation](docs/) and [didlite-examples companion repository](https://github.com/jondepalma/didlite-examples)
- **💬 GitHub Discussions**: Questions, use cases, and best practices
- **🐛 GitHub Issues**: Bug reports and feature requests
- **🔐 Security**: Report vulnerabilities to [security@didlite.io](mailto:security@didlite.io)

didlite is Apache 2.0 licensed - use it however you want. All features are freely available.

### Production Consulting (Optional)

Need help with production deployment, custom integration, or enterprise support?

- **[Forjic Technology](https://forjic.io)** - Founded by didlite creator Jon DePalma
  - Deep didlite expertise and production hardening
  - Contact: [consulting@forjic.io](mailto:consulting@forjic.io)

- **Other Options**: Hire any qualified consultant or use our free production guides

didlite is independent and community-driven. Forjic is one option for commercial support.

---

**About**: didlite is created and maintained by [Jon DePalma](https://jondepalma.com). See [SECURITY.md](.github/SECURITY.md) for security policy.

---

## 🧪 Testing & Quality

### Test Coverage (v0.2.5)

**Coverage by Module:**

| Module | Coverage | Status |
|--------|----------|--------|
| `didlite/__init__.py` | **100%** | ✅ Complete coverage |
| `didlite/core.py` | **96%** | ✅ All security-critical paths tested |
| `didlite/jws.py` | **99%** | ✅ Algorithm confusion attacks prevented |
| `didlite/keystore.py` | **93%** | ✅ All storage backends validated |
| **Overall** | **95.7%** | ✅ Production-ready (351 statements, 336 covered) |

**Test Suite Breakdown:**

| Test Category | Tests | Description |
|--------------|-------|-------------|
| **Compliance** (`test_compliance.py`) | 18 | W3C DID & RFC 7515/7519 JWT/JWS standards |
| **Core** (`test_core.py`) | 37 | Identity, DID resolution, JWK/PEM export |
| **Fuzzing** (`test_fuzzing.py`) | 32 | Malformed inputs, attack scenarios, DoS prevention |
| **Integration** (`test_integration.py`) | 5 | Cross-library compatibility (authlib) |
| **JWS** (`test_jws.py`) | 63 | Token creation/verification, headers, expiration |
| **Keystore** (`test_keystore.py`) | 49 | Storage backends, encryption, persistence |
| **OWASP Compliance** (`test_owasp_compliance.py`) | 12 | OWASP Password Storage Cheat Sheet validation |
| **Security** (`test_security.py`) | 32 | Error sanitization, input validation |
| **Total** | **248** | **245 passed, 3 skipped** |

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
