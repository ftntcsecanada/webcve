#!/bin/sh
# Build and deploy webcve on the fabriclab host. Run as root from anywhere:
#   sh /data/projects/webcve/build.sh [commit]   (default: tip of main)
set -eu

PROJ_DIR=/data/projects/webcve
REPO=git@github.com:ftntcsecanada/webcve.git
KEY=/root/.ssh/id_ed25519
IMAGE=registry.fabriclab.ca:5000/webcve
export GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"

cd "$PROJ_DIR"
HASH=${1:-$(git ls-remote "$REPO" refs/heads/main | cut -f1)}
[ -n "$HASH" ] || { echo "build: could not resolve main"; exit 1; }
echo "build: $HASH"

# Refresh the host's build inputs from the repo at that commit so they never
# drift from what's committed. mv gives new inodes, so this running script is safe.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
git -C "$TMP" init -q
git -C "$TMP" fetch -q --depth 1 "$REPO" "$HASH"
git -C "$TMP" checkout -q FETCH_HEAD
for f in Dockerfile docker-compose.yml build.sh pull.sh; do
  cp "$TMP/deploy/$f" "$PROJ_DIR/$f.new" && mv "$PROJ_DIR/$f.new" "$PROJ_DIR/$f"
done

# --no-cache: the Dockerfile clones source, so a cached layer would ship stale code
DOCKER_BUILDKIT=1 docker build --no-cache \
  --ssh default="$KEY" \
  --build-arg GIT_REF="$HASH" \
  -t "$IMAGE:$HASH" -t "$IMAGE:latest" .
docker push -q "$IMAGE:$HASH"
docker push -q "$IMAGE:latest"
docker-compose up -d

# Verify the running container is the commit we just built
for _ in $(seq 1 30); do
  [ "$(docker exec webcve cat /app/.commit 2>/dev/null)" = "$HASH" ] && break
  sleep 2
done
RUNNING=$(docker exec webcve cat /app/.commit 2>/dev/null || true)
[ "$RUNNING" = "$HASH" ] || { echo "build: running container is '$RUNNING', expected $HASH"; exit 1; }

echo "$HASH" > "$PROJ_DIR/.last_hash"
echo "build: deployed $HASH"
