#!/usr/bin/env sh
# Plain shell — Astro egress allowlist check
#
# Run on any host that sits on your Astro egress path: a jump box, bastion,
# build VM, or the node your CI agent runs on. Pure Python 3 stdlib, no root,
# no pip, no curl/wget required.
#
#   ASTRO_ORG_ID=<orgId> ASTRO_CLUSTER_ID=<clusterId> ./run.sh
#
# Optionally also export ASTRO_MODE (hosted|remote-execution) and ASTRO_CLOUD
# (aws|gcp|azure); the checker reads them from the environment. See the README.
#
# Exit codes: 0 = all reachable, 1 = something BLOCKED, 2 = warnings only.

set -e

: "${ASTRO_ORG_ID:?set ASTRO_ORG_ID}"
: "${ASTRO_CLUSTER_ID:?set ASTRO_CLUSTER_ID}"

python3 -c "import urllib.request; urllib.request.urlretrieve('https://raw.githubusercontent.com/astronomer/allowlist-test/main/astro_network_check.py', 'astro_network_check.py')" \
  || { echo "Could not download the checker. If raw.githubusercontent.com is itself blocked by your egress, that is a finding: allowlist it (or copy astro_network_check.py to this host manually) and re-run."; exit 1; }

python3 astro_network_check.py
