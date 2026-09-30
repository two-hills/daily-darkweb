#!/usr/bin/env bash
# Commit the cloud Routine's seen-state and push it to main — explicitly.
#
# Routine sessions start on their own claude/* branch. A plain `git push` then publishes
# the state to that side branch only, and the next run (which starts from main) reports
# the same items again — this happened on 2026-09-24 and 2026-09-29. Pushing HEAD:main
# removes the ambiguity, and a failure exits non-zero so the digest can warn about it.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
STATE=".state/seen.json"
MESSAGE="chore(state): advance seen-state after scheduled run"

git add -- "$STATE"
if git diff --cached --quiet -- "$STATE"; then
  echo "state: unchanged, nothing to push"
  exit 0
fi
git commit -q -m "$MESSAGE" -- "$STATE"

for attempt in 1 2 3; do
  if git push -q origin "HEAD:refs/heads/main"; then
    # The session branch now equals main. Tracking origin/main leaves nothing
    # "unpushed", so the run has no reason to publish a throwaway claude/* branch.
    git branch -q --set-upstream-to=origin/main 2>/dev/null || true
    echo "state: pushed to main ($(git rev-parse --short HEAD))"
    exit 0
  fi
  echo "state: push to main rejected (attempt ${attempt}/3); rebasing onto origin/main" >&2
  git fetch -q origin main
  if ! git rebase -q origin/main; then
    git rebase --abort
    echo "state: rebase onto origin/main conflicted; state NOT pushed" >&2
    exit 1
  fi
  sleep $((attempt * 2))
done
echo "state: NOT pushed to main; tomorrow's digest may repeat today's items" >&2
exit 1
