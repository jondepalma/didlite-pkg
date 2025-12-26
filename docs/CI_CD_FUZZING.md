# CI/CD Fuzzing Configuration

## Overview

The `test_fuzzing.py` suite uses Hypothesis for property-based testing with configurable intensity levels. The configuration automatically adapts to the execution environment to balance coverage and resource usage.

## Environment Modes

### Development Mode (Raspberry Pi / Local)
**Default Configuration:**
- Examples: 10 per test
- Shrinking: Disabled
- Duration: ~30 seconds for full suite
- Purpose: Quick validation during development

**Usage:**
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

**Usage:**
```bash
# Enable full fuzzing mode
export DIDLITE_FULL_FUZZ=1
pytest tests/test_fuzzing.py
```

## Implementation Details

### Configuration Variables

The fuzzing suite uses an environment variable to control intensity:

```python
# In your test environment
import os

# Set to "1" for full fuzzing in CI/CD
FULL_FUZZ_MODE = os.environ.get("DIDLITE_FULL_FUZZ", "0") == "1"
```

### Resource Requirements

**Development Mode (Raspberry Pi 5 8GB):**
- CPU: ~1 core for 30 seconds
- Memory: ~100MB
- Disk: Minimal (< 1MB for .hypothesis cache)

**CI/CD Mode (Cloud Runner):**
- CPU: 2+ cores recommended
- Memory: 2GB+ recommended
- Disk: ~10MB for .hypothesis cache
- Duration: 15-30 minutes

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

## Validation Checklist

Before releasing a new version, ensure:

1. ✅ All fuzzing tests pass in **CI/CD mode** (`DIDLITE_FULL_FUZZ=1`)
2. ✅ No crashes or unexpected exceptions
3. ✅ All property-based tests validate cryptographic properties
4. ✅ Coverage remains at 98%+

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

**Solution:** Reduce example count in your test configuration or increase timeout.

### Hypothesis Database Growing Too Large
**Symptom:** `.hypothesis/` directory exceeds 50MB

**Solution:** Clear the database:
```bash
rm -rf .hypothesis/
```

## References

- [Hypothesis Documentation](https://hypothesis.readthedocs.io/)
- [docs/TESTING_GUIDE.md](TESTING_GUIDE.md) - Testing best practices
- [.github/SECURITY.md](../.github/SECURITY.md) - Security policy

## Contributing

If you're setting up fuzzing for your own use case:
1. Start with development mode (10 examples)
2. Ensure tests pass locally
3. Enable full fuzzing in CI/CD only
4. Monitor resource usage and adjust as needed
