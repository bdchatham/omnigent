#!/usr/bin/env bash
# Continuously back the implementer's UNCOMMITTED work off this runner.
#
# Why: the previous runner was replaced mid-run and took 3 commits + a verified
# fix with it. Commits alone are not enough -- an implementer can work for a
# long stretch with nothing committed, so the exposure window is the whole
# working session. This snapshots the dirty tree, not just commits.
#
# Read-only against the worktree: uses `git diff` / `git ls-files --others`.
# It never touches the implementer's index, so it cannot race its commits.
set -uo pipefail

WT=/home/omnigent/workspace/wt-slack-catchup
STATE=/tmp/polly-state
INTERVAL="${1:-300}"

export GH_CONFIG_DIR="$HOME/.config/gh-polly"

while true; do
  if [ -d "$WT/.git" ] || [ -f "$WT/.git" ]; then
    cd "$WT" || { sleep "$INTERVAL"; continue; }

    mkdir -p "$STATE/snap/untracked"
    rm -rf "$STATE/snap/untracked"; mkdir -p "$STATE/snap/untracked"

    git diff                     > "$STATE/snap/worktree.patch" 2>/dev/null
    git diff --cached            > "$STATE/snap/staged.patch"   2>/dev/null
    git status --porcelain       > "$STATE/snap/status.txt"     2>/dev/null
    git rev-parse HEAD           > "$STATE/snap/base.txt"       2>/dev/null
    git log --oneline -20        > "$STATE/snap/log.txt"        2>/dev/null
    git ls-files --others --exclude-standard \
      | grep -vE '__pycache__|\.pyc$' > "$STATE/snap/untracked.txt" 2>/dev/null

    while read -r f; do
      [ -n "$f" ] || continue
      mkdir -p "$STATE/snap/untracked/$(dirname "$f")"
      cp "$f" "$STATE/snap/untracked/$f" 2>/dev/null
    done < "$STATE/snap/untracked.txt"

    # also mirror any real commits to the WIP branch
    if [ "$(git rev-list --count a0dec0b75..HEAD 2>/dev/null || echo 0)" != "0" ]; then
      /home/omnigent/workspace/.polly/polly-push.sh HEAD wip/slack-thread-catchup --force >/dev/null 2>&1
    fi

    cd "$STATE" || { sleep "$INTERVAL"; continue; }
    cp -r /home/omnigent/workspace/.polly/* "$STATE/.polly/" 2>/dev/null
    git add -A >/dev/null 2>&1
    if ! git diff --cached --quiet 2>/dev/null; then
      git commit -q -m "polly snapshot $(date -u +%FT%TZ) -- uncommitted worktree state" >/dev/null 2>&1
      if POLLY_TK="$(gh auth token 2>/dev/null)"; then
        export POLLY_TK
        git -c credential.helper= \
            -c credential.helper='!f(){ echo username=x-access-token; echo password=$POLLY_TK; };f' \
            push fork HEAD:refs/heads/polly/state --force >/dev/null 2>&1 \
          && echo "[$(date -u +%T)] snapshot pushed" \
          || echo "[$(date -u +%T)] snapshot push FAILED"
      else
        echo "[$(date -u +%T)] no token -- snapshot committed locally only"
      fi
    else
      echo "[$(date -u +%T)] no change"
    fi
  else
    echo "[$(date -u +%T)] worktree missing"
  fi
  sleep "$INTERVAL"
done
