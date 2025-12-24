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

### Performance and Benchmark Results 2025-12-23

***Environment: Raspberry Pi 5 8GB***

**Performance Test Results**

Identity Generation:
- Generated 100 identities in 0.01s
- Average: **0.09ms per identity**

Token Creation:
- Created 100 tokens in 0.01s
- Average: **0.12ms per token**

**Outcome**
The didlite library is extremely fast for cryptographic operations:
- ~11,000 identities/second generation rate
- ~8,300 tokens/second signing rate

This demonstrates the library's fitness for edge/IoT deployments where performance matters. The Ed25519 algorithm combined with PyNaCl's libsodium wrapper provides excellent performance even on ARM64 hardware.

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
        payload = didlite.verify_jws(token)
        
        print("Valid Data from:", payload['iss']) # Issuer DID is auto-embedded
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

## 🤝 Contributing
We keep this library "lite" on purpose. We only support `did:key` to ensure maximum portability for Edge AI and IoT.

## 📄 License
Apache 2.0 - Commercial use allowed.
