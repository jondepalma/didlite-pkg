# Gitea Issue Labels for didlite

This document defines the recommended label system for managing issues in the didlite Gitea repository.

## Label Philosophy

Labels should:
- Clearly indicate issue status and category
- Help filter by roadmap version
- Distinguish "lite-compatible" vs "scope-creep" features
- Enable priority triage for maintainers

## How to Create Labels in Gitea

**Via Web UI:**
1. Navigate to your repository in Gitea
2. Go to **Settings** → **Labels**
3. Click **New Label**
4. Enter name, description, and color code
5. Click **Create Label**

**Via Tea CLI:**
```bash
tea labels create --name "bug" --color "#d73a4a" --description "Something isn't working"
```

---

## Core Labels (Required)

### Type Labels
These indicate what kind of issue it is.

| Label | Color | Description | Usage |
|-------|-------|-------------|-------|
| `bug` | `#d73a4a` (red) | Something isn't working | Applied to all bug reports |
| `enhancement` | `#a2eeef` (light blue) | New feature request | Applied to all feature requests |
| `documentation` | `#0075ca` (blue) | Improvements to docs | README, CLAUDE.md, docstrings |
| `question` | `#d876e3` (purple) | Request for information | Usage questions (consider Discussions instead) |
| `security` | `#b60205` (dark red) | Security vulnerability | CVEs, crypto issues, dependency vulnerabilities |

### Status Labels
These track the lifecycle of an issue.

| Label | Color | Description | Usage |
|-------|-------|-------------|-------|
| `needs-reproduction` | `#fbca04` (yellow) | Bug report missing reproduction steps | Blocks triage until provided |
| `needs-triage` | `#ededed` (light gray) | Not yet reviewed by maintainer | Auto-applied to new issues |
| `confirmed` | `#0e8a16` (green) | Bug reproduced or feature accepted | Ready for implementation |
| `in-progress` | `#1d76db` (medium blue) | Someone is actively working on this | PR opened or assignee working |
| `blocked` | `#b60205` (dark red) | Cannot proceed (external dependency) | Waiting on upstream fix, spec clarification |
| `wontfix` | `#ffffff` (white) | Will not be implemented | Violates "lite" philosophy, out of scope |
| `duplicate` | `#cfd3d7` (gray) | Duplicate of another issue | Link to canonical issue |

### Priority Labels
These help maintainers triage work.

| Label | Color | Description | Usage |
|-------|-------|-------------|-------|
| `critical` | `#b60205` (dark red) | Breaks production deployments | Security issues, data loss, complete breakage |
| `high-priority` | `#d93f0b` (orange) | Important but has workaround | Major functionality broken with acceptable workaround |
| `medium-priority` | `#fbca04` (yellow) | Standard priority | Default for most issues |
| `low-priority` | `#0e8a16` (green) | Nice to have | Minor improvements, edge cases |

---

## Roadmap-Specific Labels

These align with the roadmap in `docs/FUTURE_UPGRADES.md`.

| Label | Color | Description | Roadmap Version |
|-------|-------|-------------|-----------------|
| `v0.2-hardening` | `#5319e7` (purple) | Production readiness, no new features | Q1 2026 |
| `v0.3-credentials` | `#5319e7` (purple) | Verifiable Credentials support | Q2 2026 |
| `v0.4-key-mgmt` | `#5319e7` (purple) | Key rotation and management | Q3 2026 |
| `v1.0-stable` | `#5319e7` (purple) | API stability and LTS | Q4 2026 |

**Usage:** Apply to feature requests that align with specific roadmap milestones.

---

## Philosophy Enforcement Labels

These protect the "lite" vision from scope creep.

| Label | Color | Description | Action |
|-------|-------|-------------|--------|
| `lite-compatible` | `#0e8a16` (green) | Aligns with zero-infrastructure philosophy | Feature is a good fit |
| `scope-creep` | `#b60205` (dark red) | Violates "lite" constraints | Likely to be rejected |
| `needs-justification` | `#fbca04` (yellow) | Feature request needs stronger use case | Request more detail |
| `breaking-change` | `#d93f0b` (orange) | Would break existing API | Requires major version bump |

**Guidance:**
- Mark as `scope-creep` if feature requires: databases, external APIs, heavy dependencies, blockchain, additional DID methods
- Mark as `lite-compatible` if feature: improves security, adds export formats, enhances DX, maintains zero-infrastructure

---

## Component Labels

These identify which part of the codebase is affected.

| Label | Color | Description | Code Location |
|-------|-------|-------------|---------------|
| `component:core` | `#c5def5` (pale blue) | AgentIdentity, DID derivation | `didlite/core.py` |
| `component:jws` | `#c5def5` (pale blue) | JWS creation/verification | `didlite/jws.py` |
| `component:build` | `#c5def5` (pale blue) | Setup, packaging, dependencies | `setup.py`, CI/CD |
| `component:tests` | `#c5def5` (pale blue) | Test suite issues | `tests/` |

---

## Platform-Specific Labels

Track platform-specific bugs.

| Label | Color | Description | Usage |
|-------|-------|-------------|-------|
| `platform:arm64` | `#fef2c0` (beige) | Raspberry Pi, AWS Graviton, Apple Silicon | ARM-specific issues |
| `platform:x86` | `#fef2c0` (beige) | Intel/AMD processors | x86-specific issues |
| `platform:windows` | `#fef2c0` (beige) | Windows-specific issue | Path separators, crypto libs |
| `platform:linux` | `#fef2c0` (beige) | Linux-specific issue | Distro-specific bugs |
| `platform:macos` | `#fef2c0` (beige) | macOS-specific issue | System library differences |

---

## Dependency Labels

Track issues related to upstream dependencies.

| Label | Color | Description | Dependency |
|-------|-------|-------------|------------|
| `dep:pynacl` | `#e99695` (pink) | Issue with PyNaCl (libsodium) | Signing/verification |
| `dep:multibase` | `#e99695` (pink) | Issue with py-multibase | DID encoding |
| `dep:python-jose` | `#e99695` (pink) | Issue with python-jose | JWT utilities |

---

## Special Workflow Labels

| Label | Color | Description | Usage |
|-------|-------|-------------|-------|
| `good-first-issue` | `#7057ff` (violet) | Easy for new contributors | Simple, well-scoped issues |
| `help-wanted` | `#008672` (teal) | Maintainer needs community help | Complex issues needing expertise |
| `upstream` | `#e99695` (pink) | Requires fix in dependency | Cannot fix in didlite directly |
| `research-needed` | `#d4c5f9` (lavender) | Needs investigation before decision | Unclear requirements, spec ambiguity |

---

## Example Label Combinations

### Critical Bug on Raspberry Pi
```
bug, critical, platform:arm64, component:core, needs-triage
```

### Feature Request: TTL Expiration
```
enhancement, v0.2-hardening, lite-compatible, high-priority
```

### Out-of-Scope Feature
```
enhancement, scope-creep, wontfix
```
**Close with:** "This conflicts with the 'lite' philosophy (requires database). Consider using veramo for enterprise SSI. See docs/FUTURE_UPGRADES.md."

### Security Vulnerability
```
security, critical, component:jws, confirmed, in-progress
```

### Documentation Improvement
```
documentation, good-first-issue, low-priority, lite-compatible
```

---

## Label Maintenance

### When to Add New Labels
- New platform support (e.g., `platform:freebsd`)
- New roadmap version (e.g., `v2.0-quantum`)
- New major component (e.g., `component:vc` if VCs are added)

### When to Remove Labels
- Completed roadmap versions (archive after release)
- Deprecated components
- Unused labels after 6 months

### Review Schedule
- **Monthly:** Audit `needs-triage` labels (should be processed weekly)
- **Quarterly:** Review `scope-creep` rejections (are we being too strict?)
- **Yearly:** Prune unused labels

---

## Tea CLI Label Management

**Create all core labels at once:**
```bash
#!/bin/bash
# Run from repository directory

# Type labels
tea labels create --name "bug" --color "#d73a4a" --description "Something isn't working"
tea labels create --name "enhancement" --color "#a2eeef" --description "New feature request"
tea labels create --name "documentation" --color "#0075ca" --description "Improvements to docs"
tea labels create --name "security" --color "#b60205" --description "Security vulnerability"

# Status labels
tea labels create --name "needs-reproduction" --color "#fbca04" --description "Bug report missing reproduction steps"
tea labels create --name "needs-triage" --color "#ededed" --description "Not yet reviewed by maintainer"
tea labels create --name "confirmed" --color "#0e8a16" --description "Bug reproduced or feature accepted"
tea labels create --name "in-progress" --color "#1d76db" --description "Someone is actively working on this"
tea labels create --name "wontfix" --color "#ffffff" --description "Will not be implemented"
tea labels create --name "duplicate" --color "#cfd3d7" --description "Duplicate of another issue"

# Priority labels
tea labels create --name "critical" --color "#b60205" --description "Breaks production deployments"
tea labels create --name "high-priority" --color "#d93f0b" --description "Important but has workaround"
tea labels create --name "medium-priority" --color "#fbca04" --description "Standard priority"
tea labels create --name "low-priority" --color "#0e8a16" --description "Nice to have"

# Roadmap labels
tea labels create --name "v0.2-hardening" --color "#5319e7" --description "Production readiness (Q1 2026)"
tea labels create --name "v0.3-credentials" --color "#5319e7" --description "Verifiable Credentials (Q2 2026)"
tea labels create --name "v0.4-key-mgmt" --color "#5319e7" --description "Key rotation (Q3 2026)"
tea labels create --name "v1.0-stable" --color "#5319e7" --description "API stability (Q4 2026)"

# Philosophy labels
tea labels create --name "lite-compatible" --color "#0e8a16" --description "Aligns with zero-infrastructure philosophy"
tea labels create --name "scope-creep" --color "#b60205" --description "Violates lite constraints"
tea labels create --name "needs-justification" --color "#fbca04" --description "Feature needs stronger use case"
tea labels create --name "breaking-change" --color "#d93f0b" --description "Would break existing API"

# Component labels
tea labels create --name "component:core" --color "#c5def5" --description "AgentIdentity, DID derivation"
tea labels create --name "component:jws" --color "#c5def5" --description "JWS creation/verification"
tea labels create --name "component:build" --color "#c5def5" --description "Setup, packaging, dependencies"
tea labels create --name "component:tests" --color "#c5def5" --description "Test suite issues"

# Platform labels
tea labels create --name "platform:arm64" --color "#fef2c0" --description "Raspberry Pi, AWS Graviton, Apple Silicon"
tea labels create --name "platform:x86" --color "#fef2c0" --description "Intel/AMD processors"
tea labels create --name "platform:windows" --color "#fef2c0" --description "Windows-specific issue"
tea labels create --name "platform:linux" --color "#fef2c0" --description "Linux-specific issue"
tea labels create --name "platform:macos" --color "#fef2c0" --description "macOS-specific issue"

# Dependency labels
tea labels create --name "dep:pynacl" --color "#e99695" --description "Issue with PyNaCl (libsodium)"
tea labels create --name "dep:multibase" --color "#e99695" --description "Issue with py-multibase"
tea labels create --name "dep:python-jose" --color "#e99695" --description "Issue with python-jose"

# Workflow labels
tea labels create --name "good-first-issue" --color "#7057ff" --description "Easy for new contributors"
tea labels create --name "help-wanted" --color "#008672" --description "Maintainer needs community help"
tea labels create --name "upstream" --color "#e99695" --description "Requires fix in dependency"
tea labels create --name "research-needed" --color "#d4c5f9" --description "Needs investigation before decision"
```

**Save as:** `scripts/setup_labels.sh`

---

## Triage Workflow

**For new bug reports:**
1. Add `needs-triage` initially
2. Verify reproduction steps exist → Remove `needs-triage`, add `needs-reproduction` if missing
3. Attempt to reproduce → Add `confirmed` if successful
4. Assign priority label (`critical`, `high-priority`, etc.)
5. Assign component label
6. Assign platform label if relevant

**For new feature requests:**
1. Add `needs-triage` initially
2. Check against FUTURE_UPGRADES.md → Add `scope-creep` or `lite-compatible`
3. If `scope-creep` → Add `wontfix`, close with explanation
4. If `lite-compatible` → Add roadmap label, priority, and `confirmed`
5. If uncertain → Add `needs-justification`, request more detail

**For questions:**
1. Add `question` label
2. Direct to GitHub Discussions or documentation
3. Close if answered (link to relevant docs)

---

## Automation Opportunities

**Gitea Actions (future):**
- Auto-add `needs-triage` to new issues
- Auto-add `needs-reproduction` if bug report missing code example
- Auto-close issues labeled `wontfix` + `scope-creep` after 7 days
- Notify maintainer on `critical` + `security` issues

**Current manual process:**
- Triage new issues weekly
- Review `needs-justification` monthly
- Close stale `needs-reproduction` after 14 days

---

## Related Documentation

- [FUTURE_UPGRADES.md](FUTURE_UPGRADES.md) - Roadmap and philosophy
- [CLAUDE.md](../CLAUDE.md) - Gitea workflow with tea CLI
- [Issue Templates](../.gitea/ISSUE_TEMPLATE/) - Bug and feature request forms
