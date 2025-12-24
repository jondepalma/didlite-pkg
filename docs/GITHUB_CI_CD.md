# GitHub CI/CD Workflows

**Status:** Planned for post-v0.2.0
**Priority:** HIGH - Required for production PyPI releases
**Target:** v0.3.0 milestone

---

## Overview

This document outlines the GitHub Actions CI/CD pipeline for `didlite`, designed with security-first principles from [SECURITY_AUDIT.md](SECURITY_AUDIT.md) Phase 4.3 (Supply Chain Security).

**Security Requirements:**
- ✅ **No long-lived API tokens** - Use OIDC trusted publishing
- ✅ **SLSA Level 3 provenance** - Verifiable build attestations
- ✅ **Minimal permissions** - Read-only by default
- ✅ **SBOM generation** - Software Bill of Materials for transparency
- ✅ **Automated security scanning** - Dependency and code vulnerabilities

---

## Workflow Architecture

### 1. Test Workflow (`.github/workflows/test.yml`)

**Purpose:** Run test suite on all PRs and commits to main/dev branches.

**Triggers:**
- `pull_request` (any branch)
- `push` to `main` or `dev`

**Matrix Strategy:**
```yaml
strategy:
  matrix:
    python-version: ['3.8', '3.9', '3.10', '3.11', '3.12']
    os: [ubuntu-latest, macos-latest, windows-latest]
```

**Key Jobs:**
1. **Lint & Type Check**
   - `ruff check didlite/`
   - `mypy didlite/`

2. **Unit Tests**
   - `pytest --cov=didlite --cov-report=xml`
   - Upload coverage to Codecov (optional)

3. **Integration Tests**
   - Run manual test scenarios from `docs/TESTING_GUIDE.md`
   - Verify interoperability with `authlib`

**Permissions:**
```yaml
permissions:
  contents: read  # Read-only access to repository
```

**Estimated Runtime:** 3-5 minutes per matrix combination

---

### 2. Security Scanning Workflow (`.github/workflows/security.yml`)

**Purpose:** Automated vulnerability scanning and SBOM generation.

**Triggers:**
- `push` to `main`
- `pull_request` (any branch)
- `schedule` - Weekly on Mondays at 00:00 UTC

**Key Jobs:**

#### 2.1 Dependency Vulnerability Scanning
```bash
# Install scanning tools
pip install pip-audit safety

# Scan for known CVEs
pip-audit --format json --output audit-report.json

# Check against Safety DB
safety check --json
```

#### 2.2 Python Security Linting
```bash
# Install bandit
pip install bandit[toml]

# Scan for common security issues
bandit -r didlite/ -f json -o bandit-report.json
```

#### 2.3 SBOM Generation
```bash
# Install CycloneDX
pip install cyclonedx-bom

# Generate SBOM in CycloneDX format
cyclonedx-py \
  --format json \
  --output sbom.json \
  --poetry  # or pip-compile if using that
```

**Artifacts:**
- `audit-report.json` (pip-audit results)
- `bandit-report.json` (security lint findings)
- `sbom.json` (Software Bill of Materials)

**Permissions:**
```yaml
permissions:
  contents: read
  security-events: write  # Upload SARIF to GitHub Security tab
```

**Fail Conditions:**
- Critical or high vulnerabilities in dependencies
- Bandit findings with severity HIGH or CRITICAL

---

### 3. PyPI Publishing Workflow (`.github/workflows/publish.yml`)

**Purpose:** Secure, verifiable package publishing to PyPI using OIDC.

**Triggers:**
- `release` (published) - Manual trigger via GitHub Releases UI

**Key Jobs:**

#### 3.1 Build Distribution
```bash
# Install build tools
pip install build

# Build wheel and sdist
python -m build --sdist --wheel --outdir dist/
```

#### 3.2 SLSA Provenance Generation
```yaml
- name: Generate SLSA Provenance
  uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
  with:
    base64-subjects: "${{ needs.build.outputs.hashes }}"
```

**Output:** `multiple.intoto.jsonl` (SLSA Level 3 attestation)

#### 3.3 Publish to PyPI (OIDC)
```yaml
- name: Publish to PyPI
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    packages-dir: dist/
    # NO API TOKEN - Uses OIDC automatically
```

**Permissions:**
```yaml
permissions:
  id-token: write  # OIDC token for PyPI
  contents: write  # Attach provenance to release
```

**Prerequisites (One-Time Setup):**

1. **Configure PyPI Trusted Publisher:**
   - Go to https://pypi.org/manage/account/publishing/
   - Add publisher:
     - Owner: `jondepalma` (or your GitHub org)
     - Repository: `didlite-pkg`
     - Workflow: `publish.yml`
     - Environment: `release` (optional, for approval gates)

2. **Create Release Environment (Optional but Recommended):**
   - GitHub → Settings → Environments → New environment: `release`
   - Add protection rule: Require manual approval before deployment
   - Restrict to `main` branch only

**Security Benefits:**
- ✅ No PyPI API tokens stored in GitHub Secrets
- ✅ Short-lived OIDC tokens (valid for ~10 minutes)
- ✅ Workflow can only publish when triggered from official release
- ✅ SLSA provenance proves binary was built by GitHub Actions (not local machine)

---

## SLSA Level 3 Verification

Users can verify the integrity of published packages:

```bash
# Install SLSA verifier
gh release download -R slsa-framework/slsa-verifier -p "*linux-amd64"
chmod +x slsa-verifier-linux-amd64

# Download package and provenance
pip download didlite --no-deps
wget https://github.com/jondepalma/didlite-pkg/releases/download/v0.2.0/multiple.intoto.jsonl

# Verify provenance
./slsa-verifier-linux-amd64 verify-artifact \
  didlite-0.2.0-py3-none-any.whl \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/jondepalma/didlite-pkg \
  --source-tag v0.2.0
```

**Expected Output:**
```
Verified signature against tlog entry index 12345678 at URL: ...
Verified build using builder "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.9.0" at commit abc123...
PASSED: Verified SLSA provenance
```

---

## SBOM Usage

The SBOM provides transparency into all dependencies:

**Viewing the SBOM:**
```bash
# Download SBOM from GitHub Actions artifacts
gh run download <run-id> -n sbom

# View dependencies
cat sbom.json | jq '.components[] | {name: .name, version: .version, licenses: .licenses}'
```

**Example Output:**
```json
{
  "name": "PyNaCl",
  "version": "1.5.0",
  "licenses": ["Apache-2.0"]
}
{
  "name": "py-multibase",
  "version": "1.0.3",
  "licenses": ["MIT"]
}
```

**Use Cases:**
- Compliance audits (license scanning)
- Vulnerability tracking (match CVEs to exact versions)
- Supply chain transparency

---

## Security Audit Compliance

This CI/CD setup addresses the following items from [SECURITY_AUDIT.md](SECURITY_AUDIT.md):

### Phase 4.3: Supply Chain Security & SLSA Compliance
- ✅ **Achieve SLSA Level 3** - Implemented via `slsa-github-generator`
- ✅ **Migrate to OIDC for PyPI publishing** - No long-lived API tokens
- ✅ **Generate SBOM** - Automated with `cyclonedx-bom`
- ✅ **Audit GitHub Actions permissions** - Minimal permissions per workflow
- ✅ **Verify package signatures** - SLSA provenance attached to releases

### Phase 4.1: Dependency Vulnerability Scan
- ✅ **Run `pip-audit`** - Automated weekly + on every PR
- ✅ **Run `safety check`** - Automated weekly
- ✅ **Check for CVEs in PyNaCl** - Covered by `pip-audit`

---

## Workflow Files (To Be Created)

### File: `.github/workflows/test.yml`
```yaml
name: Test Suite

on:
  push:
    branches: [main, dev]
  pull_request:
    branches: [main, dev]

permissions:
  contents: read

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        python-version: ['3.8', '3.9', '3.10', '3.11', '3.12']
        os: [ubuntu-latest, macos-latest, windows-latest]

    steps:
    - uses: actions/checkout@v4

    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v5
      with:
        python-version: ${{ matrix.python-version }}
        cache: 'pip'

    - name: Install dependencies
      run: |
        pip install -e ".[test]"

    - name: Run tests with coverage
      run: |
        pytest --cov=didlite --cov-report=xml --cov-report=term-missing -v

    - name: Upload coverage to Codecov
      if: matrix.os == 'ubuntu-latest' && matrix.python-version == '3.11'
      uses: codecov/codecov-action@v3
      with:
        files: ./coverage.xml
        flags: unittests
        name: codecov-umbrella
```

### File: `.github/workflows/security.yml`
```yaml
name: Security Scanning

on:
  push:
    branches: [main]
  pull_request:
    branches: [main, dev]
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Mondays

permissions:
  contents: read
  security-events: write

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'

    - name: Install scanning tools
      run: |
        pip install pip-audit safety cyclonedx-bom

    - name: Run pip-audit
      run: |
        pip-audit --format json --output audit-report.json || true

    - name: Run safety check
      run: |
        safety check --json --output safety-report.json || true

    - name: Generate SBOM
      run: |
        cyclonedx-py --format json --output sbom.json

    - name: Upload scan results
      uses: actions/upload-artifact@v4
      with:
        name: security-reports
        path: |
          audit-report.json
          safety-report.json
          sbom.json

  bandit-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'

    - name: Install bandit
      run: pip install bandit[toml]

    - name: Run bandit security linter
      run: |
        bandit -r didlite/ -f sarif -o bandit-report.sarif || true

    - name: Upload SARIF to GitHub Security
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: bandit-report.sarif
```

### File: `.github/workflows/publish.yml`
```yaml
name: Publish to PyPI

on:
  release:
    types: [published]

permissions:
  id-token: write  # OIDC for PyPI
  contents: write  # Attach provenance to release

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      hashes: ${{ steps.hash.outputs.hashes }}

    steps:
    - uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'

    - name: Install build tools
      run: pip install build

    - name: Build distribution
      run: python -m build --sdist --wheel --outdir dist/

    - name: Generate hashes for provenance
      id: hash
      run: |
        cd dist && echo "hashes=$(sha256sum * | base64 -w0)" >> $GITHUB_OUTPUT

    - name: Upload distributions
      uses: actions/upload-artifact@v4
      with:
        name: dist
        path: dist/

  provenance:
    needs: [build]
    permissions:
      id-token: write
      contents: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
    with:
      base64-subjects: "${{ needs.build.outputs.hashes }}"
      upload-assets: true

  publish:
    needs: [build, provenance]
    runs-on: ubuntu-latest
    environment: release  # Optional: Require manual approval

    steps:
    - name: Download distributions
      uses: actions/download-artifact@v4
      with:
        name: dist
        path: dist/

    - name: Publish to PyPI
      uses: pypa/gh-action-pypi-publish@release/v1
      with:
        packages-dir: dist/
        # OIDC authentication - no token needed
```

---

## Post-Deployment Verification

After first successful publish:

1. **Verify PyPI Package:**
   ```bash
   pip install didlite==0.2.0
   pip show didlite
   ```

2. **Verify SLSA Provenance:**
   ```bash
   gh release view v0.2.0 --json assets
   # Should show multiple.intoto.jsonl artifact
   ```

3. **Check GitHub Security Tab:**
   - Verify Dependabot alerts enabled
   - Check for any findings from Bandit scan

4. **Download and Inspect SBOM:**
   ```bash
   gh run list --workflow=security.yml
   gh run download <latest-run-id> -n security-reports
   cat sbom.json | jq
   ```

---

## Maintenance

**Weekly:**
- Review security scan results from scheduled runs
- Update dependencies if vulnerabilities found

**Per Release:**
- Verify SLSA provenance uploaded to GitHub Release
- Check PyPI package metadata is correct
- Announce release with provenance verification instructions

**Quarterly:**
- Audit GitHub Actions permissions
- Review and update action versions (Dependabot should automate this)
- Re-verify OIDC trust relationship with PyPI

---

## Migration from Gitea

**Gitea Workflows:** None currently exist (manual PyPI publishing)

**Migration Steps:**
1. ✅ Create `.github/workflows/` directory
2. ✅ Add `test.yml`, `security.yml`, `publish.yml`
3. ✅ Configure PyPI Trusted Publisher (one-time setup)
4. ✅ Create first GitHub Release to test OIDC publishing
5. ✅ Verify SLSA provenance generation
6. ✅ Document verification instructions in release notes

**No API Keys to Migrate:** Current Gitea setup uses manual publishing, no tokens to rotate.

---

## Future Enhancements (Post-v0.3.0)

- **CodeQL Analysis:** Enable GitHub's native code scanning
- **Fuzz Testing:** Add `atheris`-based fuzzing to security workflow
- **Performance Benchmarks:** Track performance regressions across releases
- **ARM64 Cross-Compilation:** Test on actual Raspberry Pi hardware via self-hosted runner
- **Release Automation:** Auto-generate CHANGELOG from conventional commits

---

## References

- [SLSA Framework](https://slsa.dev/)
- [PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/)
- [GitHub OIDC for Actions](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [CycloneDX SBOM](https://cyclonedx.org/)
- [pip-audit Documentation](https://github.com/pypa/pip-audit)

---

**Last Updated:** 2025-12-24
**Next Review:** After v0.2.0 release completion
