# allowlist-test

`astro_network_check.py` verifies that a host's network egress allows the
connections an Astro deployment needs. It tests the published
[Astro allowlist domains](https://www.astronomer.io/docs/astro/allowlist-domains)
over HTTPS, follows redirects (e.g. registry `307` -> Azure Blob / ACR) and
tests the redirect targets too, and when something is blocked it tells you
*where* (DNS, TCP, TLS/SNI, or HTTP) so your networking team knows what to fix.

The major usability features are:
* list of domains defined at the top of the script; easy to read and edit
* pass `clusterId` and `orgId` as arguments (`--orgId` / `--clusterId`) or as
  the `ASTRO_ORG_ID` / `ASTRO_CLUSTER_ID` environment variables
* pure Python 3 standard library — no `pip install`, no root, no third-party deps

## Quick start

```sh
# from a host on your Astro egress path (see the caveat below)
python3 astro_network_check.py --orgId <orgId> --clusterId <clusterId>
# or:
ASTRO_ORG_ID=<orgId> ASTRO_CLUSTER_ID=<clusterId> python3 astro_network_check.py
```

Exit codes:

| code | meaning |
|------|---------|
| `0`  | all endpoints reachable |
| `1`  | one or more endpoints **BLOCKED** |
| `2`  | reachable, warnings only (e.g. TLS interception detected) |

## ⚠️ Run it from the right place

The result is only meaningful when the check runs from **the same network
egress path your Astro deployments actually use** (your CI runner, worker
node, or a Remote Execution container). Cloud-hosted CI runners
(GitHub-hosted, GitLab.com shared, CircleCI cloud, Microsoft-hosted Azure
agents) egress from the CI provider's network, **not** your corporate
firewall/proxy — they will happily pass even when your real deployments are
blocked. Use a self-hosted / in-VPC runner.

## Allowlist by hostname, not IP

Astro endpoints sit behind shared, multi-cloud CDN infrastructure (Azure Front
Door, Cloudflare, GCP, AWS, Azure ACR/Blob). Their IPs are shared across many
tenants and rotate over time, so **IP-based firewall rules are fragile and will
break.** Allow the Astro domains by **FQDN / SNI** (e.g. a custom URL category),
not by IP address. This checker deliberately connects by hostname so it
exercises the same SNI-based path a real deployment does.

## Examples

Ready-to-use snippets for common CI/CD runners live in [`examples/`](examples/).
Each fetches the checker and runs it; set `ASTRO_ORG_ID` / `ASTRO_CLUSTER_ID`
for your org and cluster first.

| Runner | File |
|--------|------|
| GitHub Actions | [`examples/github-actions.yml`](examples/github-actions.yml) |
| Jenkins (declarative pipeline) | [`examples/Jenkinsfile`](examples/Jenkinsfile) |
| GitLab CI | [`examples/gitlab-ci.yml`](examples/gitlab-ci.yml) |
| Azure DevOps Pipelines | [`examples/azure-pipelines.yml`](examples/azure-pipelines.yml) |
| CircleCI | [`examples/circleci.yml`](examples/circleci.yml) |
| ArgoCD (PreSync hook) | [`examples/argocd-presync-job.yaml`](examples/argocd-presync-job.yaml) |
| Kubernetes Job (any cluster / Remote Execution) | [`examples/kubernetes-job.yaml`](examples/kubernetes-job.yaml) |
| Plain shell (jump box / VM / cron) | [`examples/run.sh`](examples/run.sh) |

---
