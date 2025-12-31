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

# 1. Update version in pyproject.toml
echo "1️⃣ Updating version in pyproject.toml..."
sed -i "s/^version = .*/version = \"${VERSION}\"/" pyproject.toml

# 2. Update CHANGELOG.md
echo "2️⃣ Updating CHANGELOG.md..."
DATE=$(date +%Y-%m-%d)
sed -i "s/## \[Unreleased\]/## [Unreleased]\n\n## [${VERSION}] - ${DATE}/" CHANGELOG.md

# 3. Commit changes
echo "3️⃣ Committing version bump..."
git add pyproject.toml CHANGELOG.md
git commit -m "chore: Bump version to ${VERSION}

${DESCRIPTION}

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"

# 4. Create git tag
echo "4️⃣ Creating git tag v${VERSION}..."
git tag -a "v${VERSION}" -m "${DESCRIPTION}"

# 5. Push to origin
echo "5️⃣ Pushing to origin..."
git push origin dev
git push origin --tags

# 6. Create GitHub release (triggers publish workflow)
echo "6️⃣ Creating GitHub release..."
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
