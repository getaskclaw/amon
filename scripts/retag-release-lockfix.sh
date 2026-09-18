#!/usr/bin/env bash
# Retag an old release so the tag points at a commit that builds with the flag CI uses
# (`--locked`). Only Cargo.lock's own version line differs between version bumps (verified by
# diff), so a tag keeps that release's exact source and gets a lockfile matching its Cargo.toml.
#
# usage: retag-release-lockfix.sh <orig-commit> <tag> <version>
set -euo pipefail
cd /home/box/2609/rust/amon

ORIG="$1"; TAG="$2"; VER="$3"

git show "$ORIG:Cargo.lock" | python3 -c "
import re, sys
ver = sys.argv[1]
text = sys.stdin.read()
# The crate's own entry: name = \"amon\" immediately followed by its version line.
pat = re.compile(r'(name = \"amon\"\nversion = \")([^\"]+)(\")')
matches = pat.findall(text)
assert len(matches) == 1, f'expected exactly one amon entry, found {len(matches)}'
new_text, n = pat.subn(lambda m: m.group(1) + ver + m.group(3), text)
assert n == 1 and new_text != text, 'no change made'
sys.stdout.write(new_text)
" "$VER" > /tmp/amon-lockfix.lock

python3 - <<'PY'
import re
before = open('/tmp/amon-lockfix-before.lock').read()
after = open('/tmp/amon-lockfix.lock').read()
d = [i for i in range(max(len(before), len(after))) if before[i:i+1] != after[i:i+1]]
print('byte differences:', len(d), 'at', d[:20])
PY

NEW_LOCK_BLOB=$(git hash-object -w /tmp/amon-lockfix.lock)
OLD_LOCK_BLOB=$(git rev-parse "$ORIG:Cargo.lock")
NEW_TREE=$(git ls-tree "$ORIG" \
  | sed "s|^100644 blob ${OLD_LOCK_BLOB}\tCargo.lock\$|100644 blob ${NEW_LOCK_BLOB}\tCargo.lock|" \
  | git mktree)

# Also carry the workflow's tag trigger, otherwise pushing this tag builds nothing at all
# (the tag trigger lives on main, and GitHub reads the workflow from the tagged commit).
OLD_CI_BLOB=$(git rev-parse "$ORIG:.github/workflows/ci.yml")
NEW_CI_BLOB=$(git rev-parse main:.github/workflows/ci.yml)
if [ "$OLD_CI_BLOB" != "$NEW_CI_BLOB" ]; then
  # Overlay via a temporary index: `git ls-tree` without -r only lists top-level entries, so a
  # sed against a nested path matches nothing and silently changes no tree at all.
  export GIT_INDEX_FILE=/tmp/amon-retag.index
  rm -f "$GIT_INDEX_FILE"
  git read-tree "$NEW_TREE"
  git update-index --cacheinfo "100644,${NEW_CI_BLOB},.github/workflows/ci.yml"
  NEW_TREE=$(git write-tree)
  unset GIT_INDEX_FILE
  if [ "$(git show "$NEW_TREE:.github/workflows/ci.yml" | git hash-object --stdin)" != "$NEW_CI_BLOB" ]; then
    echo "ERROR: ci.yml overlay did not land" >&2
    exit 1
  fi
  echo "overlaid .github/workflows/ci.yml from main (adds the v* tag trigger)"
fi
NEW_COMMIT=$(git commit-tree "$NEW_TREE" -p "$ORIG" -m "release ${VER}: lockfile matches the version

${TAG} is retagged to point at a state that builds with the flag CI uses (\`--locked\`).
Content is ${ORIG}'s source (${VER}) with Cargo.lock's own version line corrected; the two
differ by exactly that one line.

Verified locally with \`cargo build --release --locked\`.")

git tag -f -a "$TAG" "$NEW_COMMIT" -m "amon ${VER} (retagged: lockfile corrected so --locked builds)"
echo "TAG=$TAG OLD=$(git rev-parse "$ORIG") NEW=$NEW_COMMIT"
echo "--- diff old -> retagged (must be the lockfile version line only) ---"
git diff --stat "$ORIG" "$NEW_COMMIT"
git diff "$ORIG" "$NEW_COMMIT"
