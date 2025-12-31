# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

**Note:** Pre-v1.0.0 releases are under active development. Breaking changes may occur. We recommend pinning to a specific version in production.

---

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

**Email:** [security@jondepalma.net](mailto:security@jondepalma.net)

**Subject Line:** `[SECURITY] didlite - Brief description`

**Include in your report:**
1. **Description** - Clear description of the vulnerability
2. **Impact** - Potential security impact (confidentiality, integrity, availability)
3. **Affected Versions** - Which versions are affected
4. **Reproduction Steps** - Detailed steps to reproduce the issue
5. **Proof of Concept** - Code example demonstrating the vulnerability (if applicable)
6. **Suggested Fix** - Your recommendation for remediation (optional)

### What to Expect

1. **Acknowledgment** - We will acknowledge your report within **48 hours**
2. **Investigation** - We will investigate and confirm the vulnerability within **7 days**
3. **Fix Development** - We will develop and test a fix
4. **Disclosure Timeline** - We follow a **90-day coordinated disclosure** policy:
   - Day 0: Vulnerability reported
   - Day 7: Vulnerability confirmed, fix development begins
   - Day 30: Patch released (if possible)
   - Day 90: Public disclosure (if patch is not ready, we'll publish a mitigation guide)

### PGP Encryption (Optional)

For sensitive reports, you may encrypt your email using PGP:

**PGP Key:** [PGP Public Key](.github/security/didlite-security-pubkey.asc)

---

## Security Considerations

### Cryptographic Implementation

**didlite uses industry-standard cryptography:**

- **Ed25519 signatures** via [PyNaCl](https://github.com/pyca/pynacl) (libsodium wrapper)
- **PBKDF2** for key derivation in FileKeyStore (via Python's `cryptography` library)
- **Fernet** for symmetric encryption in FileKeyStore

**We do NOT implement custom cryptography.** All cryptographic operations rely on well-audited libraries.

### Known Limitations

**didlite is designed for edge/IoT/agent deployments with specific constraints:**

1. **No Key Revocation** - DIDs are derived from public keys, so compromised keys cannot be revoked without changing the DID
   - **Mitigation:** Use short-lived JWS tokens with `exp` claims (planned for v0.2.0)
   - **Mitigation:** Rotate keys periodically using key management features (planned for v0.4.0)

2. **No Network-Based DID Resolution** - `did:key` is static and self-contained (no ledger lookups)
   - **Implication:** Cannot update DID documents or add service endpoints
   - **Alternative:** Use `did:web` for dynamic resolution (requires separate infrastructure)

3. **FileKeyStore Security** - Seeds stored on disk are encrypted but vulnerable to:
   - **Host compromise:** If the server is compromised, encrypted keys can be brute-forced (PBKDF2 mitigates but doesn't eliminate risk)
   - **Memory dumps:** Decrypted keys exist in memory during operations
   - **Mitigation:** Use environment variable storage or HSM integration (see [docs/FUTURE_UPGRADES.md](docs/FUTURE_UPGRADES.md))

4. **No Built-In Rate Limiting** - JWS verification has no rate limiting
   - **Mitigation:** Implement rate limiting in your application layer

### Threat Model

**Assets:**
- Private Ed25519 keys (identity compromise)
- Encrypted seed files (offline brute-force attacks)
- JWS tokens (replay attacks, forgery attempts)

**Attackers:**
- Malicious users attempting signature forgery
- Network attackers intercepting JWS tokens (replay attacks)
- Local attackers with file system access (seed theft)

**Out of Scope:**
- Blockchain/ledger attacks (didlite doesn't use blockchains)
- DDoS attacks (application layer responsibility)
- Social engineering (user responsibility)

---

## Security Audit Status

**Current Status:** Internal security review in progress (v0.2.0 milestone)

**See:** [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) for detailed audit preparation checklist

**External Audit:** Planned for post-v0.2.0 (target: Q2 2025)

**Recommended Firms:**
- Cure53 (cryptographic audits)
- NCC Group (security consulting)
- Trail of Bits (cryptographic engineering)
- Least Authority (decentralized systems)

---

## Supply Chain Security

### SLSA Compliance Status

**didlite** follows the [SLSA Framework](https://slsa.dev/) (Supply-chain Levels for Software Artifacts) to ensure build integrity and provenance.

**Current Status: SLSA Level 2** ✅

| SLSA Level | Status | Details |
|------------|--------|---------|
| **Level 1: Build** | ✅ Complete | Scripted build process via GitHub Actions |
| **Level 2: Source** | ✅ Complete | Version-controlled source, authenticated provenance via OIDC |
| **Level 3: Hardened Builds** | 📋 Planned for v1.0.0 | Cryptographic build attestations, dependency pinning, hermetic builds |
| **Level 4: Two-Party Review** | 🔮 Future | Requires multiple maintainers (post-v1.0.0) |

**SLSA Level 2 Compliance Details:**

✅ **Version Control** - All source code in Git with full commit history
✅ **Scripted Build** - Automated builds via GitHub Actions (`.github/workflows/publish.yml`)
✅ **Build Service** - GitHub Actions generates build provenance
✅ **Authenticated Provenance** - OIDC Trusted Publisher eliminates API tokens
✅ **Service-Generated Provenance** - GitHub automatically generates attestations

**SLSA Level 3 Roadmap (v1.0.0):**

The following enhancements are planned for the v1.0.0 stable release:

🔲 **Non-Falsifiable Provenance** - Sign build attestations with GitHub's Sigstore integration
🔲 **Dependency Pinning** - Generate `requirements.txt` with cryptographic checksums
🔲 **Hermetic Builds** - Containerized builds with reproducible environments
🔲 **SLSA Provenance Generation** - Use `slsa-framework/slsa-github-generator` official action
🔲 **Provenance Verification** - Document how consumers can verify builds with `slsa-verifier`

**Why SLSA Level 2 is Sufficient for Beta:**

For pre-v1.0.0 releases, SLSA Level 2 provides strong supply chain security:
- Prevents compromised PyPI credentials (OIDC replaces API tokens)
- GitHub Actions provides auditable build logs
- Source code provenance is cryptographically verifiable
- All builds are reproducible from tagged commits

**SLSA Level 3 is reserved for production-critical packages** and will be implemented alongside our external security audit for v1.0.0.

### Dependency Vulnerability Scanning

**Automated Scanning:**

Our CI/CD pipeline includes automated dependency vulnerability scanning on every PR/push:

```yaml
# .github/workflows/test.yml (security-scan job)
- name: Run pip-audit (dependency vulnerability scan)
  run: pip-audit --desc
```

**Tools Used:**
- **pip-audit** (Official PyPA tool) - Scans against OSV (Open Source Vulnerabilities) database
- **Future:** Additional scanning tools under evaluation for v1.0.0

**Manual Auditing:**

```bash
# Check for known vulnerabilities in dependencies
pip install pip-audit
pip-audit --desc

# Review dependency tree
pip install pipdeptree
pipdeptree
```

**Dependency Update Policy:**
- Critical vulnerabilities: Patched within 48 hours
- High severity: Patched within 7 days
- Medium/Low severity: Addressed in next regular release

---

## Security Best Practices

### For Library Users

**1. Seed Management**
```python
# ❌ NEVER hardcode seeds in source code
agent = AgentIdentity(seed=b"insecure_hardcoded_seed_12345678")

# ✅ Load seeds from secure environment variables
import os
seed = os.environ.get("AGENT_SEED").encode()
agent = AgentIdentity(seed=seed)

# ✅ Or use encrypted file storage with strong password
from didlite.keystore import FileKeyStore
store = FileKeyStore("/secure/path", password="strong_random_password")
agent = store.get_or_create_identity("my-agent")
```

**2. JWS Token Validation**
```python
# ✅ Always verify JWS signatures before trusting payload
try:
    payload = verify_jws(token)
    # Process trusted payload
except BadSignatureError:
    # Reject invalid tokens
    raise ValueError("Invalid token signature")
```

**3. Dependency Security**
```bash
# ✅ Regularly audit dependencies for vulnerabilities
pip install pip-audit
pip-audit

# ✅ Keep didlite and dependencies up-to-date
pip install --upgrade didlite
```

**4. Production Deployment**
```python
# ✅ Use hardware security modules (HSM) for production keys
# (HSM integration planned for v0.4.0)

# ✅ Implement rate limiting on JWS verification endpoints
# (Application layer responsibility)

# ✅ Monitor for unusual signature verification failures
# (May indicate forgery attempts)
```

---

## Vulnerability Disclosure History

### v0.1.5 and Earlier
- No security vulnerabilities reported

---

## Security Contacts

**Primary Contact:** [security@jondepalma.net](mailto:security@jondepalma.net)
**Project Maintainer:** Jon DePalma
**GitHub Security Advisories:** [github.com/jondepalma/didlite-pkg/security/advisories](https://github.com/jondepalma/didlite-pkg/security/advisories)

---

## Responsible Disclosure Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

- *No vulnerabilities reported yet*

---

## References

### Standards & Specifications
- [W3C DID Core Specification](https://www.w3.org/TR/did-core/)
- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)
- [NIST SP 800-186 - Digital Signature Standard](https://csrc.nist.gov/publications/detail/sp/800-186/final)

### Security Best Practices
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)

---

**Last Updated:** 2025-12-31
**Version:** 1.1
