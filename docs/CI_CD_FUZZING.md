# CI/CD Fuzzing Configuration

## Overview

The `test_fuzzing.py` suite uses Hypothesis for property-based testing with configurable intensity levels. The configuration automatically adapts to the execution environment to balance coverage and resource usage.

## Environment Modes

### Development Mode (Raspberry Pi / Local)
**Default Configuration:**
- Examples: 10 per test (reduced from 500)
- Shrinking: Disabled
- Duration: ~30 seconds for full suite
- Purpose: Quick validation during development

**Environment:**
```bash
# Development mode is the default (DIDLITE_FULL_FUZZ not set)
pytest tests/test_fuzzing.py
```

### CI/CD Mode (GitHub Actions / Cloud Runners)
**Full Fuzzing Configuration:**
- Examples: 500 per test
- Shrinking: Enabled
- Duration: ~15-30 minutes for full suite
- Purpose: Comprehensive security testing before release

**Environment:**
```bash
# Enable full fuzzing mode
export DIDLITE_FULL_FUZZ=1
pytest tests/test_fuzzing.py
```

## Implementation Details

### Configuration Variables (tests/test_fuzzing.py)

```python
# Environment variable controls fuzzing intensity
FULL_FUZZ_MODE = os.environ.get("DIDLITE_FULL_FUZZ", "0") == "1"

# Example count: 500 for CI/CD, 10 for development
FUZZ_EXAMPLES = 500 if FULL_FUZZ_MODE else 10

# Phases: Full phases for CI/CD, skip shrinking for development
FUZZ_PHASES = None if FULL_FUZZ_MODE else [
    HypothesisPhase.explicit,
    HypothesisPhase.reuse,
    HypothesisPhase.generate
]
```

### Test Distribution

Total tests in fuzzing suite: **17 property-based tests + 8 attack scenario tests**

Example distribution (development mode):
- `FUZZ_EXAMPLES = 10` (full tests)
- `FUZZ_EXAMPLES//2 = 5` (medium tests)
- `FUZZ_EXAMPLES//3 = 3` (light tests)
- `FUZZ_EXAMPLES//5 = 2` (minimal tests)
- `FUZZ_EXAMPLES//10 = 1` (spot check tests)

Total examples in development mode: ~100 fuzz cases
Total examples in CI/CD mode: ~5,000 fuzz cases

## CI/CD Pipeline Configuration

### GitHub Actions Example

```yaml
name: Security Testing

on:
  pull_request:
    branches: [main, dev]
  push:
    branches: [main]

jobs:
  fuzzing:
    runs-on: ubuntu-latest
    timeout-minutes: 45

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -e ".[test]"

      - name: Run full fuzzing suite
        env:
          DIDLITE_FULL_FUZZ: "1"
        run: |
          pytest tests/test_fuzzing.py -v --tb=short

      - name: Upload fuzzing results
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: fuzzing-failures
          path: .hypothesis/
```

### GitLab CI Example

```yaml
fuzzing:
  stage: test
  image: python:3.11
  timeout: 45 minutes
  variables:
    DIDLITE_FULL_FUZZ: "1"
  script:
    - pip install -e ".[test]"
    - pytest tests/test_fuzzing.py -v --tb=short
  artifacts:
    when: on_failure
    paths:
      - .hypothesis/
```

## Resource Requirements

### Development Mode (Raspberry Pi 5 8GB)
- CPU: ~1 core for 30 seconds
- Memory: ~100MB
- Disk: Minimal (< 1MB for .hypothesis cache)

### CI/CD Mode (Cloud Runner)
- CPU: 2+ cores recommended
- Memory: 2GB+ recommended
- Disk: ~10MB for .hypothesis cache
- Duration: 15-30 minutes

## Validation Checklist

Before releasing a new version, ensure:

1. ✅ All fuzzing tests pass in **CI/CD mode** (`DIDLITE_FULL_FUZZ=1`)
2. ✅ No crashes or unexpected exceptions
3. ✅ All property-based tests validate cryptographic properties
4. ✅ Attack scenario tests pass (signature forgery, algorithm confusion, etc.)
5. ✅ Coverage remains at 98%+

## Troubleshooting

### Fuzzing Tests Timeout on Raspberry Pi
**Symptom:** Tests killed with exit code 137 (OOM)

**Solution:** Ensure `DIDLITE_FULL_FUZZ` is NOT set:
```bash
unset DIDLITE_FULL_FUZZ
pytest tests/test_fuzzing.py
```

### CI/CD Tests Too Slow
**Symptom:** Pipeline exceeds 45 minute timeout

**Solution:** Reduce `FUZZ_EXAMPLES` in CI/CD mode:
```python
FUZZ_EXAMPLES = 250 if FULL_FUZZ_MODE else 10  # Reduce from 500 to 250
```

### Hypothesis Database Growing Too Large
**Symptom:** `.hypothesis/` directory exceeds 50MB

**Solution:** Clear the database:
```bash
rm -rf .hypothesis/
```

## References

- [Hypothesis Documentation](https://hypothesis.readthedocs.io/)
- [SECURITY_AUDIT.md](../docs/SECURITY_AUDIT.md) - Phase 3.0: Fuzzing
- [THREAT_MODEL.md](../docs/THREAT_MODEL.md) - Attack scenarios
- [Issue #1](https://github.com/jondepalma/didlite-pkg/issues/1) - Security Audit Preparation
