#!/usr/bin/env bash
# tools/update-sums.sh - regenerate SHA256SUMS for every file in the repo
# (git-tracked plus new, untracked-but-not-ignored files), then print the
# hash of SHA256SUMS itself. That one hash is what a human approves: after
# reviewing a change, record it on the VM with
#   echo <hash> | sudo tee /etc/box-hardening/approved-sums.sha256
# (root-owned, 644). tools/verify-sums.sh refuses an install whose
# SHA256SUMS does not match the approved hash.
set -euo pipefail
cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.."
git ls-files -co --exclude-standard | grep -vx 'SHA256SUMS' | LC_ALL=C sort | tr '\n' '\0' | xargs -0 sha256sum >SHA256SUMS
echo "SHA256SUMS updated ($(wc -l <SHA256SUMS) files)"
echo "approve with: $(sha256sum SHA256SUMS | cut -d' ' -f1)"
