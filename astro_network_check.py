#!/usr/bin/env python3
"""
astro_network_check.py — Astro egress allowlist connectivity checker.

Run this from inside the network segment that will actually egress to Astro
(a worker node, CI host, or Remote Execution container). It proves whether
your egress firewall / proxy allows the connections an Astro deployment
needs, and when something is blocked it tells you *where* (DNS, TCP, TLS/SNI,
or HTTP) so your networking team knows what to fix.

  - Pure Python 3 standard library. No pip install, no root, no third-party
    dependencies. Works in a Jenkins `sh` step, other CI, or a plain shell.
  - Tests the published allowlist domain set:
        https://www.astronomer.io/docs/astro/allowlist-domains
  - Follows HTTP redirects (e.g. registry 307 -> Azure Blob / ACR) and tests
    each redirect target too — an unallowlisted redirect target breaks image
    pulls and DAG deploys even when the primary host is reachable.
  - Distinguishes DNS failure vs TCP block vs TLS/SNI reset. A reset
    immediately after the TLS ClientHello is the signature of an SNI /
    URL-category firewall rule (e.g. Palo Alto): the IP may be a shared CDN
    that is allowed for another vendor, while *this* hostname is not.
  - On a TLS-layer failure it runs two extra diagnostics automatically:
      * SNI differential: repeats the handshake to the same IP with no SNI
        and with a control SNI, to confirm the block keys on the hostname.
      * Unprivileged TTL walk: re-sends the ClientHello with increasing
        IP TTL to estimate how many hops away the resetting device sits
        (helps distinguish an on-prem firewall from something upstream).

Usage:
    python3 astro_network_check.py --orgId <orgId> --clusterId <clusterId>

    The IDs can also be supplied via environment variables (handy in CI):
        ASTRO_ORG_ID=<orgId> ASTRO_CLUSTER_ID=<clusterId> python3 astro_network_check.py
    Command-line flags take precedence over the environment variables.

Exit codes:
    0  all endpoints reachable
    1  one or more endpoints BLOCKED
    2  warnings only (e.g. TLS interception detected, endpoints reachable)
"""

import argparse
import http.client
import os
import re
import socket
import ssl
import sys
import time
from collections import deque

# ---------------------------------------------------------------------------
# DOMAINS TESTED — this is the single source of truth; edit it to add,
# remove, or change endpoints. All are tested over HTTPS on port 443.
#
# Each line is:  (host, kind)          with an optional 3rd "tags" field.
#
#   host   hostname to test. "{orgId}" and "{clusterId}" are filled in from
#          --orgId / --clusterId (or ASTRO_ORG_ID / ASTRO_CLUSTER_ID).
#   kind   "http"     plain HTTPS endpoint: GET /
#          "registry" container image registry: GET /v2/ (a 401 auth
#                     challenge is the healthy response) plus GET /, and any
#                     redirect target (e.g. cloud object storage) or token-auth
#                     realm it advertises is discovered and tested too
#          "bucket"   object storage: GET / (any HTTP response = reachable)
#   tags   optional 3rd field, space-separated. Recognized tags:
#          "optional"              if the host does not resolve in DNS, report
#                                  N/A instead of BLOCKED and do not fail.
#          "mode=remote-execution" only applies with --mode remote-execution;
#                                  otherwise reported N/A (not tested, not red).
#          "cloud=aws|gcp|azure"   the image-registry 307 redirect target for
#                                  that exec-plane cloud. With a matching
#                                  --cloud it is a hard requirement; with a
#                                  different --cloud it is N/A; with --cloud any
#                                  (default) a block is a WARNING, not a failure.
# ---------------------------------------------------------------------------
DOMAINS = [
    ("cloud.astronomer.io",                          "http"),
    ("api.astronomer.io",                            "http"),
    ("auth.astronomer.io",                           "http"),
    ("updates.astronomer.io",                        "http"),
    ("install.astronomer.io",                        "http"),
    ("{orgId}.astronomer.run",                       "http"),
    ("{clusterId}.external.astronomer.run",          "http",     "mode=remote-execution"),
    ("o11y.astronomer.io",                           "http"),
    ("pip.astronomer.io",                            "http"),
    ("raw.githubusercontent.com",                    "http"),
    ("pypi.org",                                     "http"),
    ("{clusterId}.registry.astronomer.run",          "registry"),
    ("images.astronomer.cloud",                      "registry"),
    ("air.astronomer.io",                            "registry"),
    ("astrocrpublic.azurecr.io",                     "registry"),
    # DAG bundle upload. Astro control-plane storage: always Azure Blob,
    # regardless of which cloud your exec plane runs on.
    ("astroproddagdeployment.blob.core.windows.net", "bucket"),
    # Image-registry 307 redirect targets for blob layer HEAD/GET during image
    # push/pull. Cloud-specific: the registry (distribution v3.1.1+) redirects
    # to the exec plane's object storage, which must be allowlisted too — the
    # registry host passing is NOT sufficient (this is what bit Equifax/GCP).
    # Real targets are bucket/account/region-specific; the allowlist entries
    # are wildcards (GCP: storage.googleapis.com, AWS: *.s3.amazonaws.com,
    # Azure: *.blob.core.windows.net) so we test a representative host per
    # cloud. Pass --cloud to enforce the one matching your exec plane.
    ("storage.googleapis.com",                       "bucket",   "cloud=gcp"),
    ("s3.amazonaws.com",                             "bucket",   "cloud=aws"),
    ("dockerstorageprod.blob.core.windows.net",      "bucket",   "cloud=azure"),
]

# HTTP paths requested per endpoint kind (see the DOMAINS comment above).
KIND_PATHS = {
    "http": ["/"],
    "registry": ["/v2/", "/"],
    "bucket": ["/"],
}

VERSION = "1.1"
USER_AGENT = "astro-network-check/%s (+https://www.astronomer.io/docs/astro/allowlist-domains)" % VERSION
ALLOWLIST_DOC = "https://www.astronomer.io/docs/astro/allowlist-domains"
MAX_REDIRECTS = 5
MAX_IPS_PER_HOST = 3
TIMEOUT = 10.0          # per-connection timeout for TLS/HTTP, seconds
CONNECT_TIMEOUT = 5.0   # TCP connect timeout (shorter: a dropped SYN is common
                        # behind enterprise firewalls, so fail fast per IP)
DIAG_TIMEOUT = 3.0      # per-attempt timeout for SNI/TTL diagnostics
MAX_TTL = 20            # cap for the firewall-locating TTL walk

# ssl.SSLCertVerificationError exists on 3.7+; fall back for older stdlibs.
CertVerifyError = getattr(ssl, "SSLCertVerificationError", ssl.CertificateError)

# Well-known public CAs the Astro endpoints legitimately use. If certificate
# verification fails but the presented issuer is one of these, the likely
# cause is a MISSING local CA trust store (common in scratch/Alpine
# containers without ca-certificates), not a TLS-intercepting proxy.
PUBLIC_CA_HINTS = (
    "digicert", "let's encrypt", "lets encrypt", "google trust",
    "globalsign", "sectigo", "microsoft", "amazon", "geotrust",
    "isrg", "baltimore", "entrust",
)


def looks_like_public_ca(issuer):
    return bool(issuer) and any(h in issuer.lower() for h in PUBLIC_CA_HINTS)


# --------------------------------------------------------------------------
# Target set
# --------------------------------------------------------------------------

def build_targets(org_id, cluster_id, mode="hosted", cloud="any"):
    """Expand the DOMAINS table (defined at the top of this file), applying the
    selected --mode and --cloud to decide which rows are required, which are
    soft (warning-only), and which are skipped as N/A."""
    targets = []
    for row in DOMAINS:
        host_template, kind = row[0], row[1]
        tags = row[2].split() if len(row) > 2 else []
        mode_tag = next((t[len("mode="):] for t in tags if t.startswith("mode=")), None)
        cloud_tag = next((t[len("cloud="):] for t in tags if t.startswith("cloud=")), None)
        skip_reason = None
        soft = False
        if mode_tag and mode_tag != mode:
            skip_reason = ("only required for --mode %s; not needed for --mode %s"
                           % (mode_tag, mode))
        elif cloud_tag:
            if cloud == "any":
                soft = True
            elif cloud != cloud_tag:
                skip_reason = ("image-registry redirect target for %s exec planes; "
                               "not applicable to --cloud %s" % (cloud_tag, cloud))
        targets.append({
            "host": host_template.format(orgId=org_id, clusterId=cluster_id),
            "kind": kind,
            "paths": KIND_PATHS[kind],
            "via": None,
            "id_derived": "{" in host_template,
            "optional": "optional" in tags,
            "skip_reason": skip_reason,
            "soft": soft,
        })
    return targets


# --------------------------------------------------------------------------
# Low-level helpers
# --------------------------------------------------------------------------

def resolve_host(host):
    """Resolve to a de-duplicated list of (family, sockaddr, ip_string)."""
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    out, seen = [], set()
    for family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            out.append((family, sockaddr, ip))
    return out


def classify_exception(exc):
    """Map an exception from connect/handshake/HTTP to (code, human text)."""
    if isinstance(exc, CertVerifyError):
        return "verify-failed", "certificate verification failed: %s" % exc
    if isinstance(exc, ssl.SSLEOFError):
        return "tls-eof", "connection closed mid-handshake (EOF)"
    if isinstance(exc, ssl.SSLError):
        return "tls-alert", "TLS error: %s" % getattr(exc, "reason", None) or str(exc)
    if isinstance(exc, ConnectionResetError):
        return "reset", "connection reset (TCP RST)"
    if isinstance(exc, ConnectionRefusedError):
        return "refused", "connection refused"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout", "timed out"
    if isinstance(exc, socket.gaierror):
        return "dns-failure", "DNS resolution failed: %s" % exc
    if isinstance(exc, OSError):
        return "os-error", "%s (errno %s)" % (exc.strerror or exc, exc.errno)
    return "error", str(exc)


def _issuer_from_verified_cert(cert):
    """Human string from ssl.getpeercert() parsed dict."""
    try:
        rdns = dict(item[0] for item in cert.get("issuer", ()))
        parts = [rdns[k] for k in ("organizationName", "commonName") if k in rdns]
        return ", ".join(parts) or None
    except Exception:
        return None


# Minimal DER walk to pull issuer strings out of an *unverified* peer cert
# (getpeercert() returns nothing useful under CERT_NONE). This is how we can
# name a TLS-inspecting proxy ("CN=Zscaler Root CA") without dependencies.

def _der_tlv(data, i):
    tag = data[i]
    i += 1
    length = data[i]
    i += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[i:i + n], "big")
        i += n
    return tag, data[i:i + length], i + length


def issuer_from_der(der):
    try:
        _tag, cert_body, _ = _der_tlv(der, 0)          # Certificate SEQUENCE
        _tag, tbs, _ = _der_tlv(cert_body, 0)          # tbsCertificate
        tag, _val, i = _der_tlv(tbs, 0)                # [0] version OR serial
        if tag == 0xA0:
            tag, _val, i = _der_tlv(tbs, i)            # serialNumber
        _tag, _val, i = _der_tlv(tbs, i)               # signature AlgorithmIdentifier
        _tag, issuer, _ = _der_tlv(tbs, i)             # issuer Name
        parts = []

        def walk(buf):
            j = 0
            while j < len(buf):
                t, v, j = _der_tlv(buf, j)
                if t in (0x0C, 0x13, 0x14, 0x16):      # UTF8/Printable/Teletex/IA5
                    parts.append(v.decode("utf-8", "replace"))
                elif t in (0x30, 0x31):                # SEQUENCE / SET
                    walk(v)

        walk(issuer)
        return ", ".join(parts) or None
    except Exception:
        return None


def probe_unverified_issuer(family, sockaddr, host, timeout):
    """Handshake without verification just to read the presented issuer."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.socket(family, socket.SOCK_STREAM) as raw:
            raw.settimeout(timeout)
            raw.connect(sockaddr)
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        return issuer_from_der(der) if der else None
    except Exception:
        return None


# --------------------------------------------------------------------------
# TLS-failure diagnostics (from the sni_probe.py POC)
# --------------------------------------------------------------------------

def _handshake_outcome(family, sockaddr, sni, timeout):
    """Attempt one no-verify handshake; return a short outcome string."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect(sockaddr)
        if sni:
            tls = ctx.wrap_socket(raw, server_hostname=sni)
        else:
            tls = ctx.wrap_socket(raw)
        version = tls.version()
        tls.close()
        return "HANDSHAKE-OK (%s)" % version
    except Exception as exc:
        code, text = classify_exception(exc)
        try:
            raw.close()
        except Exception:
            pass
        return "%s: %s" % (code.upper(), text)


def sni_differential(family, sockaddr, host, timeout):
    """
    Handshake to the same IP with the real SNI, no SNI, and a control SNI.
    If only the real SNI is reset/dropped, the firewall keys on the hostname.
    """
    return {
        "sni=%s" % host: _handshake_outcome(family, sockaddr, host, timeout),
        "sni=<none>": _handshake_outcome(family, sockaddr, None, timeout),
        "sni=example.com (control)": _handshake_outcome(family, sockaddr, "example.com", timeout),
    }


def build_client_hello(host):
    """Generate raw ClientHello bytes for `host` without touching the network."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=host)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def ttl_walk(family, sockaddr, host, timeout, max_ttl):
    """
    Unprivileged firewall locator. TCP-connect at normal TTL, then send the
    ClientHello with a limited IP TTL. If the ClientHello dies in transit we
    time out (no response); the first TTL at which a RST comes back bounds
    the hop distance of the device injecting the reset.
    """
    try:
        hello = build_client_hello(host)
    except Exception as exc:
        return {"error": "could not build ClientHello: %s" % exc, "hops": []}

    hops = []
    verdict = None
    for ttl in range(1, max_ttl + 1):
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(sockaddr)
        except OSError as exc:
            s.close()
            hops.append({"ttl": ttl, "outcome": "tcp-connect-failed: %s" % exc})
            break
        try:
            if family == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
            else:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            s.sendall(hello)
            data = s.recv(1)
            outcome = "server-replied" if data else "closed"
        except ConnectionResetError:
            outcome = "rst"
        except (socket.timeout, TimeoutError):
            outcome = "timeout"
        except OSError as exc:
            outcome = "error: %s" % exc
        finally:
            s.close()
        hops.append({"ttl": ttl, "outcome": outcome})
        if outcome == "rst":
            verdict = ("RST first injected at TTL %d -> the resetting device is "
                       "within ~%d network hop(s) of this machine." % (ttl, ttl))
            break
        if outcome in ("server-replied", "closed"):
            verdict = ("Real server responded at TTL %d with no injected reset "
                       "on this attempt." % ttl)
            break
    if verdict is None:
        verdict = "No response at any TTL <= %d (ClientHello silently dropped in transit)." % max_ttl
    return {"verdict": verdict, "hops": hops}


# --------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------

def http_fetch(host, path, ctx, timeout):
    """Single GET over a fresh connection. Returns (status, reason, headers)."""
    conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ctx)
    try:
        conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        resp = conn.getresponse()
        resp.read(2048)
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, resp.reason, headers
    finally:
        conn.close()


def parse_auth_realm(headers):
    """Pull the token-auth realm host out of a registry 401 challenge."""
    challenge = headers.get("www-authenticate", "")
    m = re.search(r'realm="(https://[^"]+)"', challenge)
    if not m:
        return None
    from urllib.parse import urlsplit
    parts = urlsplit(m.group(1))
    return parts.hostname, parts.path or "/"


def follow_http(host, path, ctx, timeout, result):
    """
    GET `path` on `host`, following same-host redirects. Cross-host redirect
    targets and registry token-auth realms are recorded as derived targets
    so they get the full DNS/TCP/TLS/HTTP treatment of their own.
    Returns True if at least one HTTP response was received.
    """
    from urllib.parse import urlsplit, urljoin
    current_path = path
    chain = []
    for _hop in range(MAX_REDIRECTS + 1):
        status, reason, headers = http_fetch(host, current_path, ctx, timeout)
        entry = {"host": host, "path": current_path, "status": status, "reason": reason}
        chain.append(entry)

        if status == 401:
            realm = parse_auth_realm(headers)
            if realm and realm[0] and realm[0] != host:
                result["derived"].append({
                    "host": realm[0], "path": realm[1],
                    "why": "registry token-auth realm advertised by %s" % host,
                })
            entry["note"] = "auth challenge (expected for a registry without credentials)"
            break

        if status in (301, 302, 303, 307, 308) and headers.get("location"):
            location = urljoin("https://%s%s" % (host, current_path), headers["location"])
            parts = urlsplit(location)
            entry["location"] = location
            if parts.scheme != "https":
                entry["note"] = "redirect to non-https target; not followed"
                break
            if parts.hostname == host:
                current_path = parts.path or "/"
                if parts.query:
                    current_path += "?" + parts.query
                continue
            result["derived"].append({
                "host": parts.hostname,
                "path": (parts.path or "/") + (("?" + parts.query) if parts.query else ""),
                "why": "HTTP %d redirect target of %s%s" % (status, host, current_path),
            })
            entry["note"] = "cross-host redirect; target will be tested separately"
            break
        break

    result["http"].append({"request_path": path, "chain": chain})
    return True


# --------------------------------------------------------------------------
# Per-target check
# --------------------------------------------------------------------------

def check_target(target):
    host = target["host"]
    r = {
        "host": host,
        "kind": target["kind"],
        "via": target.get("via"),
        "status": None,            # PASS | WARN | BLOCKED
        "stage": None,             # dns | tcp | tls | http
        "classification": None,
        "detail": [],
        "addresses": [],
        "tls": {},
        "http": [],
        "derived": [],
        "diagnostics": {},
    }

    # --- Stage 0: policy skip (mode/cloud not applicable) -----------------
    if target.get("skip_reason"):
        r.update(status="N/A", stage="policy", classification="not-applicable")
        r["detail"].append(target["skip_reason"])
        return r

    # --- Stage 1: DNS -----------------------------------------------------
    try:
        addrs = resolve_host(host)
    except socket.gaierror as exc:
        if target.get("optional"):
            r.update(status="N/A", stage="dns", classification="not-provisioned")
            r["detail"].append("Hostname does not exist in DNS: %s" % exc)
            r["detail"].append(
                "This is an optional endpoint that is not provisioned for "
                "this cluster. If you expected it to exist, verify the "
                "--clusterId value and re-run.")
            return r
        r.update(status="BLOCKED", stage="dns", classification="dns-failure")
        r["detail"].append("DNS resolution failed: %s" % exc)
        if target.get("id_derived"):
            r["detail"].append(
                "This hostname is built from your --orgId/--clusterId and only "
                "exists in public DNS for a valid ID. If the other domains "
                "resolve fine, double-check the ID before blaming DNS filtering.")
        return r
    r["addresses"] = [ip for _f, _sa, ip in addrs]

    # --- Stage 2: TCP connect ---------------------------------------------
    connected = None
    tcp_errors = []
    for family, sockaddr, ip in addrs[:MAX_IPS_PER_HOST]:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        try:
            t0 = time.monotonic()
            s.connect(sockaddr)
            s.settimeout(TIMEOUT)
            r["tcp_connect_ms"] = round((time.monotonic() - t0) * 1000)
            connected = (family, sockaddr, ip, s)
            break
        except OSError as exc:
            code, text = classify_exception(exc)
            tcp_errors.append("%s -> %s (%s)" % (ip, code, text))
            s.close()
    if connected is None:
        r.update(status="BLOCKED", stage="tcp")
        r["classification"] = "tcp-timeout" if all("timeout" in e for e in tcp_errors) else "tcp-blocked"
        tried = len(tcp_errors)
        total = len(addrs)
        scope = ("all %d resolved IP(s)" % total if tried >= total
                 else "the first %d of %d resolved IP(s)" % (tried, total))
        r["detail"].append("TCP connect to port 443 failed on %s:" % scope)
        r["detail"].extend("  " + e for e in tcp_errors)
        return r
    family, sockaddr, ip, sock = connected
    r["connected_ip"] = ip

    # --- Stage 3: TLS handshake with SNI + certificate verification --------
    http_ctx = ssl.create_default_context()
    try:
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(sock, server_hostname=host)
        cert = tls.getpeercert()
        r["tls"] = {
            "ok": True,
            "version": tls.version(),
            "issuer": _issuer_from_verified_cert(cert),
        }
        tls.close()
    except CertVerifyError as exc:
        try:
            sock.close()
        except Exception:
            pass
        issuer = probe_unverified_issuer(family, sockaddr, host, TIMEOUT)
        r["tls"] = {"ok": False, "verify_error": str(exc), "presented_issuer": issuer}
        r.update(status="WARN", stage="tls", classification="tls-interception")
        r["detail"].append("Certificate verification failed: %s" % exc)
        if issuer:
            r["detail"].append("Presented certificate issuer: %s" % issuer)
        if looks_like_public_ca(issuer):
            r["detail"].append(
                "NOTE: the presented certificate is from a public CA, so this "
                "may not be interception at all — this host may simply be "
                "missing a CA trust store. In a minimal container, install "
                "'ca-certificates'. If verification fails on EVERY host below, "
                "a missing trust store is the likely cause.")
        else:
            r["detail"].append(
                "A TLS-inspecting proxy is likely intercepting this connection. "
                "Docker/registry clients and the Astro data plane will reject the "
                "substituted certificate — exempt these hosts from SSL decryption.")
        # Continue to HTTP through the intercepting proxy to test the path.
        http_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        http_ctx.check_hostname = False
        http_ctx.verify_mode = ssl.CERT_NONE
    except Exception as exc:
        try:
            sock.close()
        except Exception:
            pass
        code, text = classify_exception(exc)
        r.update(status="BLOCKED", stage="tls", classification="tls-" + code)
        r["detail"].append("TLS handshake failed: %s" % text)
        if code in ("reset", "timeout", "tls-eof", "tls-alert", "eof"):
            r["detail"].append(
                "TCP connect to %s:443 succeeded but the handshake failed right "
                "after the ClientHello — the first packet that reveals the "
                "hostname (SNI). This is the signature of an SNI / URL-category "
                "firewall rule." % ip)
            r["diagnostics"]["sni_differential"] = sni_differential(
                family, sockaddr, host, TIMEOUT)
            r["diagnostics"]["ttl_walk"] = ttl_walk(
                family, sockaddr, host, timeout=DIAG_TIMEOUT, max_ttl=MAX_TTL)
        return r

    # --- Stage 4: HTTP GET (+ redirect / auth-realm discovery) -------------
    http_errors = []
    got_response = False
    for path in target["paths"]:
        try:
            follow_http(host, path, http_ctx, TIMEOUT, r)
            got_response = True
        except Exception as exc:
            code, text = classify_exception(exc)
            http_errors.append("GET %s -> %s (%s)" % (path, code, text))

    if not got_response:
        intercepted = r["classification"] == "tls-interception"
        r.update(status="BLOCKED", stage="http", classification="http-failure")
        if intercepted:
            r["detail"].append(
                "The TLS-intercepting proxy above completed a handshake, but "
                "every HTTP request through it failed:")
        else:
            r["detail"].append("TLS succeeded but every HTTP request failed:")
        r["detail"].extend("  " + e for e in http_errors)
        return r

    if r["status"] != "WARN":
        r["status"] = "PASS"
    r["stage"] = "complete"
    return r


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

class Palette:
    def __init__(self, enabled):
        self.enabled = enabled

    def paint(self, text, code):
        if not self.enabled:
            return text
        return "\033[%sm%s\033[0m" % (code, text)

    def status(self, s):
        return self.paint(s, {"PASS": "32", "WARN": "33", "BLOCKED": "31;1",
                              "N/A": "90"}.get(s, "0"))


def summarize_http(result):
    bits = []
    for req in result["http"]:
        last = req["chain"][-1]
        s = "GET %s -> %s" % (req["request_path"], last["status"])
        if len(req["chain"]) > 1 or last.get("location"):
            s += " (redirects followed)"
        bits.append(s)
    return "; ".join(bits)


def print_result_line(r, pal, width):
    status = pal.status("%-7s" % r["status"])
    host = "%-*s" % (width, r["host"])
    if r["status"] == "PASS":
        tail = summarize_http(r)
        tls = r.get("tls") or {}
        if tls.get("issuer"):
            tail += "  [TLS ok: %s]" % tls["issuer"]
    elif r["status"] == "WARN":
        tail = "reachable, but " + (r["classification"] or "warning")
    elif r["status"] == "N/A":
        tail = "not provisioned for this cluster (see details)"
    else:
        tail = "%s at %s stage" % (r["classification"], r["stage"])
    print("  %s %s %s" % (status, host, tail))


def print_details(r, pal):
    print()
    print(pal.paint("  %s — %s" % (r["host"], r["status"]), "1"))
    if r.get("via"):
        print("    Tested because: %s" % r["via"])
    if r["addresses"]:
        print("    Resolved IPs: %s" % ", ".join(r["addresses"]))
    for line in r["detail"]:
        print("    %s" % line)
    diff = r["diagnostics"].get("sni_differential")
    if diff:
        print("    SNI differential (same IP, different TLS SNI values):")
        for k, v in diff.items():
            print("      %-30s %s" % (k, v))
        outcomes = list(diff.values())
        if "RESET" in outcomes[0].upper() and not all("RESET" in o.upper() for o in outcomes[1:]):
            print("      => Only this hostname's SNI is reset: the firewall is "
                  "filtering on hostname/SNI category, not on the IP.")
    walk = r["diagnostics"].get("ttl_walk")
    if walk:
        if walk.get("hops"):
            hops = ", ".join("ttl=%d:%s" % (h["ttl"], h["outcome"]) for h in walk["hops"])
            print("    TTL walk of the ClientHello: %s" % hops)
        print("    TTL-walk verdict: %s" % (walk.get("verdict") or walk.get("error")))


REMEDIATION = {
    "dns-failure": (
        "DNS did not resolve. Check internal DNS forwarding and any DNS-filtering "
        "product (Umbrella, Infoblox, etc.) — the domain must be permitted there "
        "as well as on the egress firewall."),
    "tcp-timeout": (
        "TCP SYN to port 443 is being silently dropped: a layer-3/4 egress "
        "firewall rule. Allow outbound TCP 443 to this hostname. Prefer "
        "FQDN-based rules — these services sit behind CDNs and their IPs change."),
    "tcp-blocked": (
        "TCP connect to port 443 failed (refused/unreachable). Check egress "
        "firewall rules and routing for this destination."),
    "tls-reset": (
        "The TCP connection succeeds but is reset immediately after the TLS "
        "ClientHello that carries this hostname (SNI). This is characteristic of "
        "an SNI or URL-category firewall policy (e.g. Palo Alto App-ID/URL "
        "filtering). The destination IP is often a shared CDN edge that is "
        "already allowed for other vendors — the fix is to allow this *hostname*, "
        "not the IP. Add the domain to the TLS/SNI allowlist or a permitted "
        "custom URL category."),
    "tls-timeout": (
        "The TLS ClientHello is silently dropped after TCP connect — same class "
        "of hostname/SNI-based filtering as a reset, but drop instead of reset. "
        "Allow this hostname in the TLS/SNI or URL-filtering policy."),
    "tls-tls-alert": (
        "The handshake failed with a TLS-level error. If the SNI differential "
        "shows other SNIs succeed to the same IP, a middlebox is interfering "
        "with this hostname specifically."),
    "tls-tls-eof": (
        "The connection was closed mid-handshake — typically a firewall or "
        "proxy terminating the session after inspecting the SNI. Allow this "
        "hostname in the TLS/SNI or URL-filtering policy."),
    "tls-interception": (
        "TLS interception (SSL decryption) detected: the certificate presented "
        "was not issued by the expected public CA. Browsers with the corporate "
        "root CA may work, but container runtimes pulling images and Astro "
        "data-plane components will fail certificate validation. Exempt these "
        "domains from SSL decryption/inspection."),
    "http-failure": (
        "TLS completed but HTTP requests fail — likely a proxy or inspection "
        "device interfering above the TLS layer. Check web-proxy policy for "
        "these hostnames."),
}


def print_report(results, pal, started):
    if not results:
        print("\nNo endpoints were tested (interrupted before any result).")
        return

    blocked = [r for r in results if r["status"] == "BLOCKED"]
    warned = [r for r in results if r["status"] == "WARN"]
    passed = [r for r in results if r["status"] == "PASS"]
    not_applicable = [r for r in results if r["status"] == "N/A"]

    width = max(len(r["host"]) for r in results) + 2
    print()
    print("=" * 74)
    print(" RESULTS")
    print("=" * 74)
    for r in results:
        print_result_line(r, pal, width)

    problems = blocked + warned
    if problems or not_applicable:
        print()
        print("=" * 74)
        print(" DETAILS")
        print("=" * 74)
        for r in problems + not_applicable:
            print_details(r, pal)

    print()
    print("=" * 74)
    print(" SUMMARY")
    print("=" * 74)
    line = ("  %d passed, %d warnings, %d blocked"
            % (len(passed), len(warned), len(blocked)))
    if not_applicable:
        line += ", %d not applicable" % len(not_applicable)
    line += (" (of %d endpoints tested, including redirect targets) in %.1fs"
             % (len(results), time.monotonic() - started))
    print(line)

    # If cert verification failed everywhere and every issuer is a public CA,
    # it is almost certainly a missing local trust store, not interception.
    intercept_warns = [r for r in warned if r["classification"] == "tls-interception"]
    if intercept_warns and len(intercept_warns) == len(warned + blocked) and all(
            looks_like_public_ca((r.get("tls") or {}).get("presented_issuer"))
            for r in intercept_warns):
        print()
        print("  LIKELY CAUSE: certificate verification failed on every endpoint, "
              "and each")
        print("  presented a public CA certificate. This is almost certainly a "
              "MISSING CA")
        print("  trust store on THIS machine (e.g. a container without "
              "'ca-certificates'),")
        print("  not TLS interception. Install a CA bundle and re-run before "
              "escalating.")

    if problems:
        print()
        print("  What to hand your firewall/networking team:")
        seen = set()
        for r in problems:
            cls = r["classification"]
            key = (cls,)
            hosts = [x["host"] for x in problems if x["classification"] == cls]
            if key in seen:
                continue
            seen.add(key)
            advice = REMEDIATION.get(cls, "Investigate the failure detail above.")
            print()
            print("  * %s — affected: %s" % (cls, ", ".join(hosts)))
            for line in _wrap(advice, 70):
                print("      %s" % line)
        derived_blocked = [r for r in blocked if r.get("via")]
        if derived_blocked:
            print()
            print("  NOTE: %d blocked endpoint(s) are redirect/auth targets of the "
                  "primary domains:" % len(derived_blocked))
            for r in derived_blocked:
                print("      %s  (%s)" % (r["host"], r["via"]))
            print("      Image pulls and DAG deploys follow these redirects, so the "
                  "primary domain passing is NOT sufficient — these hosts must be "
                  "allowlisted too.")
    else:
        print()
        print("  All published Astro allowlist endpoints are reachable from this host.")

    print()
    print("  Reference allowlist: %s" % ALLOWLIST_DOC)
    print()


def _wrap(text, width):
    words, lines, cur = text.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        lines.append(cur)
    return lines


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verify egress-firewall allowlisting of Astro endpoints "
                    "from inside your network.",
        epilog="Run from the network segment that will actually egress to "
               "Astro (worker/CI host). See %s" % ALLOWLIST_DOC)
    parser.add_argument("--orgId", default=os.environ.get("ASTRO_ORG_ID"),
                        help="Astro organization ID (used for <orgId>.astronomer.run); "
                             "defaults to $ASTRO_ORG_ID")
    parser.add_argument("--clusterId", default=os.environ.get("ASTRO_CLUSTER_ID"),
                        help="Astro cluster ID (used for <clusterId>.registry/"
                             ".external.astronomer.run); defaults to $ASTRO_CLUSTER_ID")
    parser.add_argument("--mode", choices=["hosted", "remote-execution"],
                        default=os.environ.get("ASTRO_MODE", "hosted"),
                        help="Deployment mode. 'remote-execution' additionally "
                             "requires <clusterId>.external.astronomer.run; "
                             "'hosted' (default) does not test it. Defaults to "
                             "$ASTRO_MODE or hosted.")
    parser.add_argument("--cloud", choices=["aws", "gcp", "azure", "any"],
                        default=os.environ.get("ASTRO_CLOUD", "any"),
                        help="Cloud your Astro exec plane runs on. The image "
                             "registry 307-redirects to cloud-specific object "
                             "storage (gcp=storage.googleapis.com, "
                             "aws=*.s3.amazonaws.com, azure=*.blob.core.windows.net) "
                             "that must also be allowlisted. Set this to test the "
                             "right target as a hard requirement; 'any' (default) "
                             "tests all three as warnings only. Defaults to "
                             "$ASTRO_CLOUD or any.")
    opts = parser.parse_args(argv)
    if not opts.orgId:
        parser.error("provide --orgId or set ASTRO_ORG_ID")
    if not opts.clusterId:
        parser.error("provide --clusterId or set ASTRO_CLUSTER_ID")

    targets = build_targets(opts.orgId, opts.clusterId, opts.mode, opts.cloud)
    pal = Palette(sys.stdout.isatty())

    print("astro-network-check v%s  |  Python %s  |  %s"
          % (VERSION, sys.version.split()[0], time.strftime("%Y-%m-%d %H:%M:%S %Z")))
    print("Mode: %s   Cloud: %s" % (opts.mode, opts.cloud))
    print("Testing %d endpoint(s), timeout %.0fs. Redirect targets discovered "
          "along the way are tested too." % (len(targets), TIMEOUT))
    print("If endpoints are blocked this can take several minutes (blocked "
          "connections must time out); a clean run finishes in seconds.")
    if opts.cloud == "any":
        print("NOTE: --cloud not set. The image-registry redirect target is "
              "cloud-specific and will be reported as a WARNING only. Re-run "
              "with --cloud <aws|gcp|azure> matching your exec plane to test it "
              "as a hard requirement.")
    proxies = {k: v for k, v in os.environ.items()
               if k.lower() in ("http_proxy", "https_proxy") and v}
    if proxies:
        print("NOTE: proxy environment variables are set (%s) but this script "
              "tests DIRECT egress, which is what the Astro data plane uses. "
              "If your environment requires a proxy for all egress, failures "
              "below may reflect that policy."
              % ", ".join(sorted(proxies)))
    print()

    started = time.monotonic()
    queue = deque(targets)
    tested = {}
    results = []
    try:
        while queue:
            t = queue.popleft()
            if t["host"] in tested:
                continue
            if t.get("skip_reason"):
                print("  skipping %s (%s)" % (t["host"], t["skip_reason"]), flush=True)
            else:
                print("  checking %s ..." % t["host"], flush=True)
            r = check_target(t)
            if t.get("soft") and r["status"] == "BLOCKED":
                r["status"] = "WARN"
                r["detail"].append(
                    "Reported as a WARNING, not a failure, because --cloud was "
                    "not set. This is the image-registry redirect target for one "
                    "cloud; re-run with --cloud <aws|gcp|azure> matching your "
                    "Astro exec plane to test it as a hard requirement.")
            tested[t["host"]] = r
            results.append(r)
            for d in r["derived"]:
                if d["host"] in tested or any(q["host"] == d["host"] for q in queue):
                    continue
                queue.append({
                    "host": d["host"],
                    "kind": "derived",
                    "paths": [d["path"]],
                    "via": d["why"],
                })
    except KeyboardInterrupt:
        print("\nInterrupted; reporting results so far.")

    print_report(results, pal, started)

    blocked = any(r["status"] == "BLOCKED" for r in results)
    warned = any(r["status"] == "WARN" for r in results)
    return 1 if blocked else (2 if warned else 0)


if __name__ == "__main__":
    sys.exit(main())
