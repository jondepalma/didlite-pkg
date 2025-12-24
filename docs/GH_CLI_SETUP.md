# GitHub CLI (gh) Installation Guide

This guide covers installing and configuring the GitHub CLI (`gh`) on Raspberry Pi OS (Debian-based ARM64).

---

## Installation on Raspberry Pi OS

### Option 1: Using APT Repository (Recommended)

```bash
# Update package list
sudo apt update

# Install required dependencies
sudo apt install -y curl gpg

# Add GitHub CLI repository key
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg

# Add GitHub CLI repository to sources
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null

# Update package list
sudo apt update

# Install GitHub CLI
sudo apt install -y gh
```

### Option 2: Using Pre-built Binary (Alternative)

If APT installation fails on ARM64:

```bash
# Download latest ARM64 release
wget https://github.com/cli/cli/releases/latest/download/gh_*_linux_arm64.tar.gz

# Extract archive
tar -xzf gh_*_linux_arm64.tar.gz

# Move binary to PATH
sudo mv gh_*_linux_arm64/bin/gh /usr/local/bin/

# Verify installation
gh --version
```

---

## Verification

Check that `gh` is installed correctly:

```bash
gh --version
```

**Expected Output:**
```
gh version 2.40.0 (2024-01-15)
https://github.com/cli/cli/releases/tag/v2.40.0
```

---

## Authentication

Authenticate `gh` with your GitHub account:

```bash
# Start interactive authentication
gh auth login
```

**Follow the prompts:**

1. **What account do you want to log into?**
   - Select: `GitHub.com`

2. **What is your preferred protocol for Git operations?**
   - Select: `SSH` (recommended, since you're already using SSH for Gitea)

3. **Upload your SSH public key to GitHub?**
   - Select: `Yes` (if you want to use the same SSH key)
   - Or select: `No` and manually add your SSH key later at https://github.com/settings/keys

4. **How would you like to authenticate GitHub CLI?**
   - Select: `Login with a web browser`
   - Copy the 8-character code displayed
   - Press Enter to open browser (or manually go to https://github.com/login/device)
   - Paste the code and authorize

**Verification:**
```bash
# Check authentication status
gh auth status
```

**Expected Output:**
```
github.com
  ✓ Logged in to github.com as jondepalma (/home/pi/.config/gh/hosts.yml)
  ✓ Git operations protocol: ssh
  ✓ Token: *******************
```

---

## Configuration

### Set Default Repository (Optional)

When working in the `didlite-pkg` directory, `gh` will auto-detect the repository from git remotes. However, you can explicitly set it:

```bash
# Navigate to repository
cd /home/pi/dev-projects/didlite-pkg

# Verify gh can detect the repo
gh repo view
```

**Note:** This will initially fail because the GitHub remote doesn't exist yet. After completing Phase 1 (adding GitHub remote), this command will work.

---

## Common gh Commands for Migration

Once you've completed Phase 1 (creating GitHub repository and adding remote):

### Repository Management
```bash
# View repository details
gh repo view

# Clone repository
gh repo clone jondepalma/didlite-pkg
```

### Labels
```bash
# Create a label
gh label create "bug" --description "Something isn't working" --color "D73A4A"

# List all labels
gh label list

# Delete a label
gh label delete "bug"
```

### Milestones
```bash
# Create milestone
gh milestone create "v0.2.0 - Hardening" --description "Security hardening" --due-date "2025-12-31"

# List milestones
gh milestone list

# View milestone details
gh milestone view "v0.2.0 - Hardening"
```

### Issues
```bash
# Create issue
gh issue create --title "Bug title" --body "Description"

# List issues
gh issue list

# View issue
gh issue view 123

# Close issue
gh issue close 123
```

### Pull Requests
```bash
# Create PR
gh pr create --base main --head dev --title "PR title" --body "Description"

# List PRs
gh pr list

# View PR
gh pr view 42

# Merge PR
gh pr merge 42
```

### Releases
```bash
# Create release (triggers PyPI publish workflow)
gh release create v0.2.0 --title "v0.2.0 - Hardening" --notes "Release notes here"

# List releases
gh release list

# View release
gh release view v0.2.0
```

---

## SSH Key Setup (If Needed)

If you selected "No" during `gh auth login` for SSH key upload, manually add your SSH key:

### 1. Generate SSH Key (if you don't have one)
```bash
# Generate Ed25519 key (modern, secure)
ssh-keygen -t ed25519 -C "your_email@example.com"

# Press Enter to accept default location (~/.ssh/id_ed25519)
# Enter passphrase (recommended) or leave empty
```

### 2. Add SSH Key to SSH Agent
```bash
# Start SSH agent
eval "$(ssh-agent -s)"

# Add key to agent
ssh-add ~/.ssh/id_ed25519
```

### 3. Copy Public Key
```bash
# Display public key
cat ~/.ssh/id_ed25519.pub
```

### 4. Add to GitHub
```bash
# Using gh CLI
gh ssh-key add ~/.ssh/id_ed25519.pub --title "Raspberry Pi 5"

# Or manually:
# Go to https://github.com/settings/keys
# Click "New SSH key"
# Paste the public key
# Give it a title (e.g., "Raspberry Pi 5")
```

### 5. Test SSH Connection
```bash
ssh -T git@github.com
```

**Expected Output:**
```
Hi jondepalma! You've successfully authenticated, but GitHub does not provide shell access.
```

---

## Comparison: tea (Gitea) vs gh (GitHub)

| Operation | Gitea (tea) | GitHub (gh) |
|-----------|-------------|-------------|
| Create issue | `tea issues create` | `gh issue create` |
| List issues | `tea issues list` | `gh issue list` |
| Create PR | `tea pulls create` | `gh pr create` |
| List PRs | `tea pulls list` | `gh pr list` |
| Create milestone | `tea milestones create` | `gh milestone create` |
| Create label | `tea labels create` | `gh label create` |
| View repo | `tea repos` | `gh repo view` |

**Key Differences:**
- `tea` uses plural commands (`issues`, `pulls`, `milestones`)
- `gh` uses singular commands (`issue`, `pr`, `milestone`)
- Both auto-detect repository from git remotes when run in repo directory
- Both support `--repo` flag to explicitly specify repository

---

## Troubleshooting

### gh: command not found

**Solution:**
- Verify installation: `which gh`
- Check PATH: `echo $PATH`
- Re-install using Option 1 or Option 2 above

### Authentication Failed

**Solution:**
```bash
# Logout and re-authenticate
gh auth logout
gh auth login
```

### Repository Not Found

**Solution:**
- Ensure you're in the correct directory: `pwd`
- Check git remotes: `git remote -v`
- Verify GitHub remote exists after Phase 1 completion
- Use `--repo` flag: `gh issue list --repo jondepalma/didlite-pkg`

### SSH Connection Failed

**Solution:**
```bash
# Test SSH connectivity
ssh -T git@github.com

# If fails, verify SSH key is added to GitHub
gh ssh-key list

# Add SSH key if missing
gh ssh-key add ~/.ssh/id_ed25519.pub
```

---

## Next Steps

1. ✅ Install `gh` using instructions above
2. ✅ Authenticate with GitHub account
3. ✅ Verify SSH key is configured
4. ⏳ Complete Phase 1 (create GitHub repo, add remote, push branches)
5. ⏳ Return to migration plan for remaining phases

---

**References:**
- [GitHub CLI Official Docs](https://cli.github.com/manual/)
- [GitHub CLI Installation](https://github.com/cli/cli#installation)
- [GitHub SSH Setup](https://docs.github.com/en/authentication/connecting-to-github-with-ssh)

---

**Last Updated:** 2025-12-24
