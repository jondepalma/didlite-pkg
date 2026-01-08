#!/bin/bash
# Release automation script for didlite
# Usage: ./scripts/release.sh 0.2.4 "Bug fix release"

set -e

VERSION=$1
DESCRIPTION=$2

if [ -z "$VERSION" ] || [ -z "$DESCRIPTION" ]; then
    echo "Usage: ./scripts/release.sh <version> <description>"
    echo "Example: ./scripts/release.sh 0.2.4 'Bug fix release'"
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

# 1. Update version in pyproject.toml
echo "1️⃣ Updating version in pyproject.toml..."
sed -i "s/^version = .*/version = \"${VERSION}\"/" pyproject.toml

# 2. Update version in didlite/__init__.py
echo "2️⃣ Updating version in didlite/__init__.py..."
sed -i "s/^__version__ = .*/__version__ = \"${VERSION}\"/" didlite/__init__.py

# 3. Update CHANGELOG.md
echo "3️⃣ Updating CHANGELOG.md..."
DATE=$(date +%Y-%m-%d)

# Only insert if version doesn't already exist
if ! grep -q "## \[${VERSION}\]" CHANGELOG.md; then
    sed -i "s/## \[Unreleased\]/## [Unreleased]\n\n## [${VERSION}] - ${DATE}/" CHANGELOG.md
else
    # Version already exists, just update the date
    sed -i "s/## \[${VERSION}\] - .*/## [${VERSION}] - ${DATE}/" CHANGELOG.md
fi

# 4. Commit changes
echo "4️⃣ Committing version bump..."
git add pyproject.toml didlite/__init__.py CHANGELOG.md
git commit -m "chore: Bump version to ${VERSION}

${DESCRIPTION}

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"

# 5. Create git tag
echo "5️⃣ Creating git tag v${VERSION}..."
git tag -a "v${VERSION}" -m "${DESCRIPTION}"

# 6. Push to origin
echo "6️⃣ Pushing to origin/main..."
git push origin main
git push origin --tags

# 7. Create GitHub release (triggers publish workflow)
echo "7️⃣ Creating GitHub release..."
gh release create "v${VERSION}" \
    --title "v${VERSION}" \
    --notes "${DESCRIPTION}

See [CHANGELOG.md](https://github.com/jondepalma/didlite-pkg/blob/main/CHANGELOG.md) for full details.

⚠️ **Beta Status:** This release has not undergone an independent security audit. See [SECURITY.md](https://github.com/jondepalma/didlite-pkg/blob/main/.github/SECURITY.md) for details." \
    --draft

echo ""
echo "✅ Release draft created!"
echo "👉 Review at: https://github.com/jondepalma/didlite-pkg/releases"
echo "👉 Publish the release to trigger PyPI upload via OIDC"
