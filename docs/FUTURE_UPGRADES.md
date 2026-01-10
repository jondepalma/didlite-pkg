# Future Upgrades and Roadmap

**Document Purpose:** High-level roadmap for didlite's evolution while maintaining the "lite" philosophy.

**Last Updated:** December 2025

---

## Design Philosophy

didlite follows the **"SQLite for decentralized identity"** approach:
- Not for every use case, but essential for edge/IoT/agent deployments
- Simple, predictable, and zero-infrastructure
- Easy to replace when you outgrow it
- Focused on the 80% use case

---

## Target Use Cases

**Where didlite excels:**
- ✅ AI agent frameworks needing identity layer
- ✅ IoT sensor networks with embedded ML
- ✅ Edge gateways processing data locally
- ✅ Offline-first systems
- ✅ Prototyping before scaling to full SSI infrastructure

**Where didlite is NOT the right choice:**
- ❌ Regulated credential issuance (healthcare, finance)
- ❌ Long-lived verifiable credentials with revocation
- ❌ Integration with existing PKI/enterprise SSI
- ❌ Blockchain-anchored identity

---

## Planned Features

### v0.2.x - Hardening (Current - v0.2.5)
**Focus:** Production readiness and stability

**Completed in v0.2.2 (2025-12-29):**
- [x] Security audit - Phase 5 complete (7 vulnerability fixes)
- [x] JWK and PEM export/import
- [x] TTL expiration support
- [x] Pluggable key storage (MemoryKeyStore, EnvKeyStore, FileKeyStore)
- [x] W3C DID and JWT/JWS standards compliance verification
  - 75 compliance tests added (W3C DID Core, RFC 7515/7517/7519)
  - Algorithm enforcement (prevent "None Algorithm" attacks)
  - Compact JSON serialization (RFC 7515)
  - Future-dating protection with clock skew tolerance
- [x] Lazy import optimization (cryptography only loaded when needed)
- [x] Performance benchmarking (Raspberry Pi 5: ~11k identities/sec, ~8.3k tokens/sec)

**Completed in v0.2.3 (2025-12-30):**
- [x] JWS header enhancements (custom headers support for plugins)
- [x] Breaking change: verify_jws() returns (header, payload) tuple
- [x] extract_signer_did() helper function for fast DID extraction
- [x] Test coverage improved to 97% (232 tests)
- [x] Plugin ecosystem readiness (AP2, OAuth, SIOP)

**Completed in v0.2.5: (2025-12-30):**
- [x] Dependency security audit (automated scanning)

**Remaining**
- [ ] External security audit (penetration testing)

**Deliverable:** ✅ Production-safe library with stable API achieved

---

### v0.3.0 - Verifiable Credentials (Planned)
**Focus:** Minimal VC support for agent claims

**Potential features being considered:**
- W3C VC data model implementation
- Credential issuance and verification APIs
- Simple claim structures (no JSON-LD complexity)
- TTL-based expiration (no revocation infrastructure)

**Note:** These features are under consideration and may change based on community feedback.

---

### v0.4.0 - Key Management (Planned)
**Focus:** Key rotation for long-lived deployments

**Potential features being considered:**
- Key derivation (HD wallet style)
- Key rotation protocols
- Multi-key support
- Integration with OS keychains/HSM

**Note:** These features are under consideration and may change based on community feedback.

---

### v1.0.0 - Stable API (Target: Late 2026)
**Focus:** API freeze and long-term support commitment

- API stability guarantee
- Backward compatibility commitment
- Performance optimization
- Production case studies

---

## Migration Path: From Lite to Enterprise

didlite is designed with **exit ramps**, not lock-in.

**Phase 1: Pure didlite (0-1000 agents)**
- Use did:key for all identities
- Sign data with JWS
- Verify signatures locally
- No infrastructure required

**Phase 2: Add Metadata (1000-10000 agents)**
- External registry for agent metadata
- Still use didlite for signing
- Add service discovery separately

**Phase 3: Hybrid (10000+ agents)**
- Keep didlite for edge devices
- Migrate gateway to enterprise SSI (veramo/aries)
- Use JWK export for interoperability

**Phase 4: Full Enterprise SSI**
- Replace didlite with full SSI stack
- Add revocation infrastructure
- Maintain did:key backward compatibility

---

## Contributing Ideas

We welcome community input on future features! Before opening a feature request:

1. **Check if it aligns with the "lite" philosophy**
   - Does it add zero-infrastructure value?
   - Is it essential for edge/IoT deployments?
   - Can it be done without heavy dependencies?

2. **Consider if it should be a plugin**
   - Advanced features can be separate packages
   - Example: `didlite-vc` for full VC support
   - Example: `didlite-web` for did:web resolver

3. **Open a GitHub issue with**
   - Use case description
   - Why existing features don't solve it
   - Impact on library size/complexity

---

## Standards Compliance

didlite aims to comply with:
- W3C DID Core Specification (did:key method)
- RFC 7515 (JSON Web Signature)
- RFC 8032 (EdDSA)
- W3C Verifiable Credentials (basic support in v0.3.0)

---

## Community & Ecosystem

**Target Integrations:**
- Agent-to-Agent Communication
- Agent-Payment-Protocol
- OAuth and SIOP v2
- LangChain (agent identity layer)
- AutoGen (agent authentication)
- Raspberry Pi (official examples)
- AWS IoT Greengrass (edge identity)

**Academic/Research:**
- Multi-agent system identity
- SSI research testbed
- Edge AI deployments

---

## Long-Term Vision

**Success means:**
1. Becoming the default lightweight identity for securing AI Agents, Edge, and IoT computing.
2. Clear migration path to enterprise SSI
3. Active community beyond original author
4. External security audit passed
5. Production deployments in AI Agents and edge/IoT

**We measure success by utility, not feature count.**

---

## Questions or Suggestions?

Open a GitHub issue or start a discussion. We're building this for the community and welcome your input!
