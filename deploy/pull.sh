#!/bin/sh
# Auto-deploy: rebuild when main moves. Root crontab entry:
#   */5 * * * * /bin/sh /data/projects/webcve/pull.sh
PROJ_DIR=/data/projects/webcve
LOG="$PROJ_DIR/pull.log"
REPO=git@github.com:ftntcsecanada/webcve.git
export GIT_SSH_COMMAND="ssh -i /root/.ssh/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"

# One build at a time
exec 9>"$PROJ_DIR/.pull.lock"
flock -n 9 || exit 0

REMOTE=$(git ls-remote "$REPO" refs/heads/main | cut -f1)
if [ -z "$REMOTE" ]; then
  echo "$(date): ERROR could not fetch remote hash" >> "$LOG"
  exit 1
fi
# Quiet when nothing changed, and don't retry a commit that already failed
[ "$REMOTE" = "$(cat "$PROJ_DIR/.last_hash" 2>/dev/null)" ] && exit 0
[ "$REMOTE" = "$(cat "$PROJ_DIR/.failed_hash" 2>/dev/null)" ] && exit 0

echo "$(date): main is $REMOTE, rebuilding" >> "$LOG"
if sh "$PROJ_DIR/build.sh" "$REMOTE" >> "$LOG" 2>&1; then
  rm -f "$PROJ_DIR/.failed_hash"
  echo "$(date): deployed $REMOTE" >> "$LOG"
else
  echo "$REMOTE" > "$PROJ_DIR/.failed_hash"
  echo "$(date): ERROR build failed for $REMOTE (will retry on the next commit, or run build.sh by hand)" >> "$LOG"
fi
