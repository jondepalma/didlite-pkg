# Local Development Setup for `didlite`

Since we are actively developing `didlite` alongside the Orchestrator and SDK, we don't want to publish to PyPI for every little change. We will use Python's "Editable Install" mode.

### 1. Directory Structure
Ensure your projects are siblings in your workspace:
/workspace
  /didlite-pkg      <-- The Library
  /orchestrator     <-- The Consumer
  /agent-sdk        <-- The Consumer

### 2. Install in Editable Mode
Go to your Orchestrator (or SDK) directory and install `didlite` as a local link.

```bash
# Inside /workspace/orchestrator
pip install -e ../didlite-pkg
