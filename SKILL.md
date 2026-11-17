---
name: astro-network-check
description: Check whether a network's egress firewall or proxy allows the connections an Astro deployment needs, using astro_network_check.py in this repo. Use when someone is setting up or troubleshooting Astro (astro deploy, image push or pull, Dag upload, Remote Execution agents), sees connection resets, timeouts or TLS errors reaching Astronomer endpoints, or wants to verify their allowlist before onboarding.
---

# Astro egress allowlist check

`astro_network_check.py` tests the published [Astro allowlist domains](https://www.astronomer.io/docs/astro/allowlist-domains) over HTTPS and reports where each one fails: DNS, TCP, TLS/SNI or HTTP. It follows redirects (the image registry redirects to cloud object storage) and tests those targets too. It is a single file, pure Python 3 standard library: no `pip install`, no root.

The result only means something if the script runs on the same network path your Astro deployments use: a worker node, a self-hosted CI runner, a Remote Execution container, or a jump box on that segment. Hosted CI runners (GitHub-hosted, GitLab.com shared, CircleCI cloud, Microsoft-hosted) egress from the provider's network, not your firewall, and will pass even when your real deployments are blocked. A sandboxed agent environment is the same story.

## Before running

1. Confirm with the user that this machine is on the egress path they care about. If it isn't, say so and offer the matching file in `examples/` (GitHub Actions, Jenkins, GitLab, Azure Pipelines, CircleCI, Argo CD, Kubernetes Job, plain shell) instead of running it here.
2. Get the **organization ID** and **cluster ID** from the user. Don't guess them. They appear in the Astro UI and in the deployment's `*.astronomer.run` URLs.
3. Ask whether the deployment is `hosted` or `remote-execution`, and which cloud the execution plane runs on (`aws`, `gcp` or `azure`). Both change what is a hard requirement. Without `--cloud` the cloud-specific storage endpoints are only warnings.
4. Tell the user what the script does on the network before you run it: it connects out to the Astro endpoints, and it looks up the machine's public IP by calling `api.ipify.org`, `checkip.amazonaws.com` and `icanhazip.com`. Its output includes the hostname and the local and public IPs.

## Run

```sh
python3 astro_network_check.py --orgId <orgId> --clusterId <clusterId> [--mode remote-execution] [--cloud aws|gcp|azure]
```

The IDs, mode and cloud can also come from `ASTRO_ORG_ID`, `ASTRO_CLUSTER_ID`, `ASTRO_MODE` and `ASTRO_CLOUD`. A clean run takes seconds. When endpoints are blocked it can take several minutes because blocked connections must time out, so allow a long timeout and don't interrupt it early. The script tests direct egress and ignores `HTTP_PROXY` / `HTTPS_PROXY` (it prints a note if they are set), because that is how the Astro data plane connects.

Exit codes: `0` all reachable, `1` one or more endpoints blocked, `2` reachable with warnings only (for example TLS interception detected).

## Reading the result

Report what the script printed, per endpoint, and don't invent causes it didn't show. The stage where an endpoint fails points at the layer to fix:

| Fails at | Usually means |
|---|---|
| DNS | The resolver or DNS filtering doesn't return the name. |
| TCP connect | A firewall drops or rejects port 443 to that address. |
| TLS, reset right after the ClientHello | An SNI or URL-category rule on the firewall. The script confirms it automatically by retrying with no SNI and with a control SNI, and estimates how many hops away the resetting device is with a TTL walk. If only the real hostname is reset, the rule keys on the hostname. |
| TLS, interception warning | A proxy or inspection device is re-signing traffic with its own CA. That CA has to be trusted by whatever runs Astro workloads. |
| HTTP | The connection works but the response is blocked or rewritten. |

Two points to include when relevant:

- Astro endpoints sit behind shared, multi-cloud CDN infrastructure whose IPs rotate. Recommend allowing the domains by **FQDN / SNI**, not by IP address. IP-based rules are fragile and are the most common cause of "allowed, but still reset".
- A reachable registry host isn't enough. Image push and pull and Dag upload redirect to object storage (cloud-specific, plus the Dag upload bucket), and those targets must be allowlisted too.

## What not to do

- Don't change firewall, proxy or DNS settings. Hand the findings to whoever owns them.
- Don't edit the `DOMAINS` list at the top of the script to make a failure disappear. It mirrors the published allowlist; if the docs have changed, update from the docs page.
- Don't run it repeatedly in a loop against a blocked network. One run, then act on the result.

## Sharing the result

Give the user a short summary: which endpoints passed, which failed and at which stage, and the exit code. If they are working with Astronomer support, suggest attaching the full script output to the ticket. It contains the hostname and IP addresses, so the user should decide whether that is fine to share.
