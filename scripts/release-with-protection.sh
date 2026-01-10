#!/bin/bash
# Release automation script for didlite (with branch protection)
# Usage: ./scripts/release-with-protection.sh 0.2.5 "Bug fix release"
#
# This version works with branch protection by:
# 1. Creating version bump on a temporary branch
# 2. Creating a PR for the version bump
# 3. Auto-merging the PR (requires admin bypass)
# 4. Creating the release

set -e

VERSION=$1
DESCRIPTION=$2

if [ -z "$VERSION" ] || [ -z "$DESCRIPTION" ]; then
    echo "Usage: ./scripts/release-with-protection.sh <version> <description>"
    echo "Example: ./scripts/release-with-protection.sh 0.2.5 'Bug fix release'"
    echo ""
    echo "Note: Version should NOT include 'v' prefix"
    exit 1
fi

echo "📦 Preparing release v${VERSION}"
echo "Description: ${DESCRIPTION}"
echo ""

# 0. Verify we're on main branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo "❌ ERROR: Must be on 'main' branch to create a release"
    echo "   Current branch: $CURRENT_BRANCH"
    echo "   Run: git checkout main && git pull origin main"
    exit 1
fi

# 1. Create temporary branch for version bump
TEMP_BRANCH="release/v${VERSION}"
echo "1️⃣ Creating temporary branch: ${TEMP_BRANCH}..."
git checkout -b "${TEMP_BRANCH}"

# 2. Update version in pyproject.toml
echo "2️⃣ Updating version in pyproject.toml..."
sed -i "s/^version = .*/version = \"${VERSION}\"/" pyproject.toml

# 3. Update version in didlite/__init__.py
echo "3️⃣ Updating version in didlite/__init__.py..."
sed -i "s/^__version__ = .*/__version__ = \"${VERSION}\"/" didlite/__init__.py

# 4. Update CHANGELOG.md
echo "4️⃣ Updating CHANGELOG.md..."
DATE=$(date +%Y-%m-%d)
sed -i "s/## \[Unreleased\]/## [Unreleased]\n\n## [${VERSION}] - ${DATE}/" CHANGELOG.md

# 5. Commit changes
echo "5️⃣ Committing version bump..."
git add pyproject.toml didlite/__init__.py CHANGELOG.md
git commit -m "chore: Bump version to ${VERSION}

${DESCRIPTION}

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"

# 6. Push branch
echo "6️⃣ Pushing branch to origin..."
git push origin "${TEMP_BRANCH}"

# 7. Create and auto-merge PR
echo "7️⃣ Creating PR for version bump..."
PR_URL=$(gh pr create --base main --head "${TEMP_BRANCH}" \
    --title "chore: Bump version to v${VERSION}" \
    --body "Automated version bump for v${VERSION} release.

${DESCRIPTION}

This PR updates:
- \`pyproject.toml\` - version field
- \`didlite/__init__.py\` - __version__ variable
- \`CHANGELOG.md\` - date stamp for v${VERSION}

🤖 Generated with [Claude Code](https://claude.com/claude-code)" \
    --assignee @me)

echo "   PR created: ${PR_URL}"

# Extract PR number from URL
PR_NUMBER=$(echo "${PR_URL}" | grep -oP '\d+$')

echo "8️⃣ Merging PR #${PR_NUMBER}..."
gh pr merge "${PR_NUMBER}" --squash --admin

# 9. Switch back to main and pull
echo "9️⃣ Updating local main branch..."
git checkout main
git pull origin main

# 10. Create git tag
echo "🔟 Creating git tag v${VERSION}..."
git tag -a "v${VERSION}" -m "${DESCRIPTION}"
git push origin "v${VERSION}"

# 11. Create GitHub release (triggers publish workflow)
echo "1️⃣1️⃣ Creating GitHub release..."
gh release create "v${VERSION}" \
    --title "v${VERSION}" \
    --notes "${DESCRIPTION}

See [CHANGELOG.md](https://github.com/jondepalma/didlite-pkg/blob/main/CHANGELOG.md) for full details.

⚠️ **Beta Status:** This release has not undergone an independent security audit. See [SECURITY.md](https://github.com/jondepalma/didlite-pkg/blob/main/.github/SECURITY.md) for details." \
    --draft

# 12. Cleanup
echo "1️⃣2️⃣ Cleaning up temporary branch..."
git push origin --delete "${TEMP_BRANCH}"
git branch -d "${TEMP_BRANCH}"

echo ""
echo "✅ Release draft created!"
echo "👉 Review at: https://github.com/jondepalma/didlite-pkg/releases"
echo "👉 Publish the release to trigger PyPI upload via OIDC"
