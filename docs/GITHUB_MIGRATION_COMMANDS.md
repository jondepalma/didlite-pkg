# GitHub Migration Commands

This document contains the commands to set up labels and milestones on GitHub after repository migration.

**Prerequisites:**
- GitHub repository created and accessible
- `gh` CLI installed and authenticated
- Run these commands from the repository directory

---

## Phase 3: Create Labels

Run these commands to create all labels used in the project:

```bash
# Navigate to repository
cd /home/pi/dev-projects/didlite-pkg

# Component labels
gh label create "component:core" \
  --description "Core identity and DID functionality" \
  --color "0052CC"

gh label create "component:jws" \
  --description "JWS token creation/verification" \
  --color "0052CC"

gh label create "component:keystore" \
  --description "Key storage and management" \
  --color "0052CC"

gh label create "component:tests" \
  --description "Testing infrastructure" \
  --color "0052CC"

# Type labels (bug and enhancement already exist by default, but we'll ensure they have correct colors)
gh label create "bug" \
  --description "Something isn't working" \
  --color "D73A4A" \
  --force  # --force updates existing label

gh label create "enhancement" \
  --description "New feature or request" \
  --color "A2EEEF" \
  --force

gh label create "documentation" \
  --description "Documentation improvements" \
  --color "0075CA"

# Priority labels
gh label create "high-priority" \
  --description "Critical for milestone completion" \
  --color "D93F0B"

gh label create "medium-priority" \
  --description "Important but not blocking" \
  --color "FBCA04"

gh label create "low-priority" \
  --description "Nice to have" \
  --color "C2E0C6"

# Philosophy labels
gh label create "lite-compatible" \
  --description "Aligns with didlite's minimal philosophy" \
  --color "7057FF"

# Milestone labels
gh label create "v0.2-hardening" \
  --description "Security hardening milestone" \
  --color "5319E7"
```

**Verify labels were created:**
```bash
gh label list
```

**Expected output:** 11 labels total (component:core, component:jws, component:keystore, component:tests, bug, enhancement, documentation, high-priority, medium-priority, low-priority, lite-compatible, v0.2-hardening)

---

## Phase 4: Create Milestones

Create the v0.2.0 milestone:

```bash
gh milestone create "v0.2.0 - Hardening" \
  --description "Security audit preparation, supply chain hardening (SLSA Level 3, OIDC publishing), and production readiness features" \
  --due-date "2025-12-31"
```

**Verify milestone was created:**
```bash
gh milestone list
```

**Expected output:**
```
TITLE                  DESCRIPTION                                       DUE DATE   STATE
v0.2.0 - Hardening     Security audit preparation, supply chain hard...  Dec 31     open
```

---

## Phase 5: Manual Issue Migration

Recreate the 2 open issues from Gitea on GitHub:

### Issue #8: Security Audit Preparation

```bash
gh issue create \
  --title "Security Audit Preparation: Code review and vulnerability assessment" \
  --body "## Overview

This issue tracks the security audit preparation work outlined in [docs/SECURITY_AUDIT.md](https://github.com/jondepalma/didlite-pkg/blob/main/docs/SECURITY_AUDIT.md).

**Goal:** Prepare the codebase for external security audit by conducting internal review, fixing identified issues, and documenting security considerations.

**Status:** In Progress
**Priority:** HIGH - Required before production adoption and v1.0.0 release

## Scope

This is **preparation work** for an external audit, not the audit itself. The external audit would be a separate paid engagement with a security firm (planned for post-v0.2.0).

## Key Phases

### Phase 1: Internal Code Review
- [ ] Cryptographic implementation review (PyNaCl, libsodium boundary)
- [ ] Input validation & sanitization
- [ ] Timing attack analysis
- [ ] Error handling & information disclosure

### Phase 2: Security Documentation
- [x] Create SECURITY.md policy
- [ ] Document threat model
- [ ] Document cryptographic choices

### Phase 3: Security Testing
- [ ] Fuzzing & property-based testing (Hypothesis)
- [ ] Malformed input tests
- [ ] Attack scenario tests
- [ ] Cryptographic property tests

### Phase 4: Dependency Security
- [ ] Dependency vulnerability scan (pip-audit, safety)
- [ ] Dependency review
- [ ] Supply chain security & SLSA Level 3 compliance
- [ ] OIDC migration for PyPI publishing

### Phase 5: Compliance & Standards
- [ ] W3C DID specification compliance
- [ ] JWT/JWS standards compliance
- [ ] OWASP best practices review

### Phase 6: External Audit Preparation
- [ ] Create audit package
- [ ] Create security checklist
- [ ] Code annotation

## Success Criteria

- ✅ No critical or high vulnerabilities in internal review
- ✅ All dependencies up-to-date with no known CVEs
- ✅ SECURITY.md policy published
- ✅ Threat model documented
- ✅ 98%+ test coverage maintained
- ✅ Security-focused tests added

## References

- [SECURITY_AUDIT.md](https://github.com/jondepalma/didlite-pkg/blob/main/docs/SECURITY_AUDIT.md)
- [SECURITY.md](https://github.com/jondepalma/didlite-pkg/blob/main/.github/SECURITY.md)

**Migrated from Gitea Issue #8**" \
  --label "enhancement,high-priority,lite-compatible,v0.2-hardening" \
  --milestone "v0.2.0 - Hardening"
```

### Issue #9: Migration Documentation

```bash
gh issue create \
  --title "Migration Documentation: Guide for transitioning to enterprise SSI" \
  --body "## Overview

Create documentation to help users understand when and how to migrate from didlite to enterprise SSI solutions.

**Goal:** Provide clear guidance on didlite's limitations and migration paths to full-featured SSI stacks.

## Motivation

didlite is intentionally minimal (\`did:key\` only). Users who outgrow this scope need guidance on:
- When to migrate (specific use case triggers)
- What alternatives exist (veramo, aries, spruce)
- How to migrate existing DIDs/credentials
- Interoperability considerations

## Proposed Documentation

### File: \`docs/MIGRATION_GUIDE.md\`

**Sections:**
1. **When to Migrate**
   - Need for DID methods beyond \`did:key\` (\`did:web\`, \`did:ethr\`)
   - Verifiable Credential revocation requirements
   - Service endpoint needs (DID Document resolution)
   - Blockchain integration requirements

2. **Migration Targets**
   - **veramo** - Full-featured TypeScript SSI framework
   - **aries** - Python-based hyperledger framework
   - **spruce** - Rust-based DIDKit
   - Comparison matrix (features, deployment size, complexity)

3. **Migration Strategy**
   - Exporting existing identities (seed/key export)
   - Transitioning JWS tokens to new formats
   - Backward compatibility considerations
   - Dual-stack operation (gradual migration)

4. **Interoperability**
   - W3C DID Core compliance verification
   - JWT/JWS standard compliance
   - Testing with external verifiers

5. **Anti-Patterns**
   - What NOT to do when migrating
   - Common mistakes (hardcoding DIDs, losing seeds)

## Success Criteria

- Clear decision tree for migration timing
- Working code examples for exporting to veramo/aries
- Tested migration paths with real credentials
- No disruption to existing didlite users

## References

- [FUTURE_UPGRADES.md](https://github.com/jondepalma/didlite-pkg/blob/main/docs/FUTURE_UPGRADES.md) - Anti-Use Cases section
- W3C DID Core Specification

**Migrated from Gitea Issue #9**" \
  --label "documentation,lite-compatible,medium-priority,v0.2-hardening" \
  --milestone "v0.2.0 - Hardening"
```

**Verify issues were created:**
```bash
gh issue list --milestone "v0.2.0 - Hardening"
```

---

## Verification Checklist

After running all commands:

- [ ] 11 labels created (`gh label list`)
- [ ] 1 milestone created (`gh milestone list`)
- [ ] 2 issues created and assigned to milestone (`gh issue list --milestone "v0.2.0 - Hardening"`)
- [ ] Issue templates visible in GitHub UI (go to repository → Issues → New Issue)
- [ ] SECURITY.md visible in GitHub UI (go to repository → Security tab)

---

## GitHub Repository Settings (Manual Configuration)

### 1. Set Default Branch

- Navigate to: Settings → Branches
- Set default branch to: `main`

### 2. Branch Protection Rules

**For `main` branch:**
- Settings → Branches → Add branch protection rule
- Branch name pattern: `main`
- Enable:
  - ✅ Require pull request before merging
  - ✅ Require approvals (1)
  - ✅ Require status checks to pass before merging (once CI is set up)
  - ✅ Do not allow bypassing the above settings

### 3. Enable Security Features

- Settings → Code security and analysis
- Enable:
  - ✅ Dependency graph
  - ✅ Dependabot alerts
  - ✅ Dependabot security updates
  - ✅ Secret scanning (if available for public repos)

### 4. Configure GitHub Actions Permissions

- Settings → Actions → General
- Workflow permissions: **Read repository contents and packages permissions**
- ✅ Allow GitHub Actions to create and approve pull requests (optional)

**Why:** Prevents compromised workflows from pushing malicious code (per SECURITY_AUDIT.md)

---

## Next Steps

After completing this migration:

1. ✅ Commit migration artifacts to repository:
   ```bash
   git add .github/ docs/
   git commit -m "chore: Complete GitHub migration (issue templates, SECURITY.md, documentation)

   - Add GitHub issue templates (bug_report.yml, feature_request.yml)
   - Add SECURITY.md vulnerability disclosure policy
   - Update CLAUDE.md for GitHub workflow (gh CLI)
   - Add GitHub CI/CD documentation (post-v0.2.0)
   - Add GH CLI setup guide

   Migrated from Gitea to GitHub as primary repository.
   Gitea retained as backup mirror.

   🤖 Generated with [Claude Code](https://claude.com/claude-code)

   Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"

   git push-all main
   ```

2. ✅ Test issue creation flow:
   - Go to GitHub repository → Issues → New Issue
   - Verify templates appear correctly

3. ✅ Update PyPI package metadata (future release):
   - Change `url` in `setup.py` to GitHub URL
   - Update documentation links in package description

4. ⏳ Implement CI/CD workflows (post-v0.2.0):
   - See [docs/GITHUB_CI_CD.md](GITHUB_CI_CD.md)

---

**Last Updated:** 2024-12-24
