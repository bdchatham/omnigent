#!/usr/bin/env bash
# polly orchestration plumbing: push a ref to the fork using the device-flow
# token, bypassing the platform's seidroid credential helper.
#
# The platform helper in ~/.gitconfig answers FIRST and wins, so an inline
# `-c credential.helper=...` is silently ignored. The empty `-c credential.helper=`
# below RESETS the helper list before ours is added. DO NOT REMOVE IT.
# Symptom when forgotten: "Permission to bdchatham/omnigent.git denied to
# bdchatham" even though the REST API can create refs on that same repo.
#
# usage: polly-push.sh <src-ref> <dest-branch> [--force]
set -euo pipefail

SRC="${1:?src ref required}"
DEST="${2:?dest branch required}"
FORCE="${3:-}"

export GH_CONFIG_DIR="$HOME/.config/gh-polly"
if ! POLLY_TK="$(gh auth token 2>/dev/null)" || [ -z "$POLLY_TK" ]; then
  echo "polly-push: no device-flow token in $GH_CONFIG_DIR -- re-run gh auth login" >&2
  exit 1
fi
export POLLY_TK

git -c credential.helper= \
    -c credential.helper='!f(){ echo username=x-access-token; echo password=$POLLY_TK; };f' \
    push fork "${SRC}:refs/heads/${DEST}" ${FORCE:+--force} 2>&1 \
  | sed 's/gh[pou]_[A-Za-z0-9]*/<redacted>/g'
