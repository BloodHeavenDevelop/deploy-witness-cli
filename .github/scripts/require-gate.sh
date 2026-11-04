#!/usr/bin/env bash
# require-gate.sh <commit> — exits 0 only when the release gate passed for exactly
# this commit: a `bench` workflow run on a push to main whose head is <commit>,
# completed with conclusion "success". A successful run of any other commit — the
# previous release, a parent, a pull request — does not count: an old result never
# certifies a new build (DW-95).
#
# Needs GH_TOKEN (actions: read) and GITHUB_REPOSITORY, which GitHub Actions sets.
set -euo pipefail

sha=${1:?usage: require-gate.sh <full commit sha>}
case "$sha" in
  *[!0-9a-f]* | "") echo "require-gate: '$sha' is not a commit sha" >&2; exit 2 ;;
esac
[ ${#sha} -eq 40 ] || { echo "require-gate: give the full 40-character sha, not '$sha'" >&2; exit 2; }

runs=$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/bench.yml/runs?head_sha=${sha}&event=push&per_page=50" \
  --jq "[.workflow_runs[] | select(.head_sha == \"${sha}\" and .head_branch == \"main\")]")

total=$(jq length <<<"$runs")
passed=$(jq '[.[] | select(.status == "completed" and .conclusion == "success")] | length' <<<"$runs")
if [ "$passed" -eq 0 ]; then
  echo "require-gate: no successful release gate for ${sha} (${total} bench run(s) of this commit on main:" \
    "$(jq -r '[.[] | "\(.id) \(.status)/\(.conclusion // "-")"] | join(", ") | if . == "" then "none" else . end' <<<"$runs"))." \
    "A gate passed by another commit does not certify this one." >&2
  exit 1
fi
jq -r '[.[] | select(.conclusion == "success")][0] | "require-gate: \(.head_sha) passed the release gate in bench run \(.id) (\(.html_url)), finished \(.updated_at)"' <<<"$runs"
