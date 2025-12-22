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

    # Inside /workspace/orchestrator
    pip install -e ../didlite-pkg

**What this does:**
It creates a symbolic link in your `site-packages` pointing to your source code.
* If you change code in `/didlite-pkg`, the Orchestrator sees it **immediately**.
* No need to rebuild or reinstall.

### 3. Verify Installation
Run this quick python snippet to prove it works on your ARM64 machine:

    import didlite.core
    import didlite.jws

    # Create an identity
    agent = didlite.core.AgentIdentity()
    print(f"Agent DID: {agent.did}")

    # Sign a test payload
    token = didlite.jws.create_jws(agent, {"status": "online"})
    print(f"Token: {token}")
