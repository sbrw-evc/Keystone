#!/bin/sh
# Builds the deploy bundle of a release, as .github/workflows/release.yml did for GitHub releases.
# Usage: .onedev/bundle.sh <image> <version> <where the bundle is downloaded from> [output directory, default dist]
# Writes <output>/keystone-<version>-deploy.tar.gz, SHA256SUMS and notes.md (the release description). Needs yq.
set -eu
APP=keystone; IMAGE=$1; VERSION=$2; URL=$3; OUT=${4:-dist}; TAG=v$VERSION
DIR="$OUT/$APP-$VERSION"
rm -rf "$OUT"; mkdir -p "$DIR"
for f in docker-compose.yml .env.example install.sh openbao README.md README.ru.md LICENSE; do
  [ -e "$f" ] && cp -r "$f" "$DIR/"
done
# The application runs from the published image: no build section, the image of this version.
IMG="$IMAGE:$VERSION" yq -i '(.services[] | select(has("build"))) |= (del(.build) | .image = strenv(IMG) | .pull_policy = "missing")' "$DIR/docker-compose.yml"
tar -C "$OUT" -czf "$OUT/$APP-$VERSION-deploy.tar.gz" "$APP-$VERSION"
rm -rf "$DIR"
( cd "$OUT" && sha256sum "$APP-$VERSION-deploy.tar.gz" > SHA256SUMS )
NOTES=".github/release-notes/$TAG.md"
# shellcheck disable=SC2016 # the backticks are Markdown, not an expansion
{ [ -f "$NOTES" ] && cat "$NOTES" && echo; \
  printf '## Install\n\n```bash\ncurl -L %s | tar xz\ncd %s-%s && ./install.sh\n```\n\nImage: `%s:%s`\n' \
    "$URL" "$APP" "$VERSION" "$IMAGE" "$VERSION"; } > "$OUT/notes.md"
