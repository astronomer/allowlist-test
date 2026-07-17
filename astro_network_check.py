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
    python3 astro_network_check.py --org-id <orgId> --cluster-id <clusterId>

    Optional:
      --timeout N       per-connection timeout in seconds (default 10)
      --json            emit machine-readable JSON instead of the text report
      --list            print the domains that would be tested, then exit
      --include STR     only test hosts containing STR (repeatable)
      --no-ttl-walk     skip the TTL-walk diagnostic on TLS failures
      --no-color        disable ANSI colors

Exit codes:
    0  all endpoints reachable
    1  one or more endpoints BLOCKED
    2  warnings only (e.g. TLS interception detected, endpoints reachable)
"""

import argparse
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time
from collections import deque

VERSION = "1.0"
USER_AGENT = "astro-network-check/%s (+https://www.astronomer.io/docs/astro/allowlist-domains)" % VERSION
ALLOWLIST_DOC = "https://www.astronomer.io/docs/astro/allowlist-domains"
MAX_REDIRECTS = 5
MAX_IPS_PER_HOST = 3

# ssl.SSLCertVerificationError exists on 3.7+; fall back for older stdlibs.
CertVerifyError = getattr(ssl, "SSLCertVerificationError", ssl.CertificateError)


# --------------------------------------------------------------------------
# Target set
# --------------------------------------------------------------------------

def build_targets(org_id, cluster_id):
    """The published allowlist domain set, parameterized by org/cluster."""
    targets = []

    def add(host, label, kind, paths, id_derived=False):
        targets.append({
            "host": host, "label": label, "kind": kind,
            "paths": paths, "via": None, "id_derived": id_derived,
        })

    # Plain HTTPS endpoints
    add("cloud.astronomer.io", "Astro UI", "http", ["/"])
    add("api.astronomer.io", "Astro API", "http", ["/"])
    add("auth.astronomer.io", "Astro authentication", "http", ["/"])
    add("updates.astronomer.io", "Runtime update service", "http", ["/"])
    add("install.astronomer.io", "Astro CLI install", "http", ["/"])
    add("%s.astronomer.run" % org_id, "Deployment endpoint (*.astronomer.run)", "http", ["/"],
        id_derived=True)
    add("%s.external.astronomer.run" % cluster_id, "Cluster external endpoint", "http", ["/"],
        id_derived=True)
    add("o11y.astronomer.io", "Observability ingest", "http", ["/"])
    add("pip.astronomer.io", "Astronomer pip index", "http", ["/"])
    add("raw.githubusercontent.com", "GitHub raw content", "http", ["/"])
    add("pypi.org", "PyPI", "http", ["/"])

    # Image registries. These are the ones that bite: they answer on /v2/,
    # commonly 307-redirect blobs to Azure Blob / ACR, and hand out token
    # auth realms — all of which must ALSO be allowlisted.
    add("%s.registry.astronomer.run" % cluster_id,
        "Deployment image registry", "registry", ["/v2/"], id_derived=True)
    add("images.astronomer.cloud",
        "Astro image host (redirects to backing store)", "registry", ["/v2/", "/"])
    add("air.astronomer.io",
        "Astro Runtime images (redirects to ACR)", "registry", ["/v2/", "/"])
    add("astrocrpublic.azurecr.io",
        "Azure Container Registry (Astro Runtime)", "registry", ["/v2/"])

    # Object storage
    add("astroproddagdeployment.blob.core.windows.net",
        "DAG deploy storage (Azure Blob)", "bucket", ["/"])

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
                "why": "HTTP %d redirect target of %s%s" % (status, host, path),
            })
            entry["note"] = "cross-host redirect; target will be tested separately"
            break
        break

    result["http"].append({"request_path": path, "chain": chain})
    return True


# --------------------------------------------------------------------------
# Per-target check
# --------------------------------------------------------------------------

def check_target(target, opts):
    host = target["host"]
    r = {
        "host": host,
        "label": target["label"],
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

    # --- Stage 1: DNS -----------------------------------------------------
    try:
        addrs = resolve_host(host)
    except socket.gaierror as exc:
        r.update(status="BLOCKED", stage="dns", classification="dns-failure")
        r["detail"].append("DNS resolution failed: %s" % exc)
        if target.get("id_derived"):
            r["detail"].append(
                "This hostname is built from your --org-id/--cluster-id and only "
                "exists in public DNS for a valid ID. If the other domains "
                "resolve fine, double-check the ID before blaming DNS filtering.")
        return r
    r["addresses"] = [ip for _f, _sa, ip in addrs]

    # --- Stage 2: TCP connect ---------------------------------------------
    connected = None
    tcp_errors = []
    for family, sockaddr, ip in addrs[:MAX_IPS_PER_HOST]:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(opts.timeout)
        try:
            t0 = time.monotonic()
            s.connect(sockaddr)
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
        r["detail"].append("TCP connect to port 443 failed on every resolved IP:")
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
        issuer = probe_unverified_issuer(family, sockaddr, host, opts.timeout)
        r["tls"] = {"ok": False, "verify_error": str(exc), "presented_issuer": issuer}
        r.update(status="WARN", stage="tls", classification="tls-interception")
        r["detail"].append("Certificate verification failed: %s" % exc)
        if issuer:
            r["detail"].append("Presented certificate issuer: %s" % issuer)
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
                family, sockaddr, host, opts.timeout)
            if not opts.no_ttl_walk:
                r["diagnostics"]["ttl_walk"] = ttl_walk(
                    family, sockaddr, host,
                    timeout=min(opts.timeout, 3.0), max_ttl=opts.max_ttl)
        return r

    # --- Stage 4: HTTP GET (+ redirect / auth-realm discovery) -------------
    http_errors = []
    got_response = False
    for path in target["paths"]:
        try:
            follow_http(host, path, http_ctx, opts.timeout, r)
            got_response = True
        except Exception as exc:
            code, text = classify_exception(exc)
            http_errors.append("GET %s -> %s (%s)" % (path, code, text))

    if not got_response:
        r.update(status="BLOCKED", stage="http", classification="http-failure")
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
        return self.paint(s, {"PASS": "32", "WARN": "33", "BLOCKED": "31;1"}.get(s, "0"))


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
    else:
        tail = "%s at %s stage" % (r["classification"], r["stage"])
    print("  %s %s %s" % (status, host, tail))


def print_details(r, pal):
    print()
    print(pal.paint("  %s — %s (%s)" % (r["host"], r["status"], r["label"]), "1"))
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


def print_report(results, opts, pal, started):
    blocked = [r for r in results if r["status"] == "BLOCKED"]
    warned = [r for r in results if r["status"] == "WARN"]
    passed = [r for r in results if r["status"] == "PASS"]

    width = max(len(r["host"]) for r in results) + 2
    print()
    print("=" * 74)
    print(" RESULTS")
    print("=" * 74)
    for r in results:
        print_result_line(r, pal, width)

    problems = blocked + warned
    if problems:
        print()
        print("=" * 74)
        print(" DETAILS")
        print("=" * 74)
        for r in problems:
            print_details(r, pal)

    print()
    print("=" * 74)
    print(" SUMMARY")
    print("=" * 74)
    print("  %d passed, %d warnings, %d blocked (of %d endpoints tested, "
          "including redirect targets) in %.1fs"
          % (len(passed), len(warned), len(blocked), len(results),
             time.monotonic() - started))

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
    parser.add_argument("--org-id", required=True,
                        help="Astro organization ID (used for <orgId>.astronomer.run)")
    parser.add_argument("--cluster-id", required=True,
                        help="Astro cluster ID (used for <clusterId>.registry/"
                             ".external.astronomer.run)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="per-connection timeout in seconds (default: 10)")
    parser.add_argument("--max-ttl", type=int, default=20,
                        help="max TTL for the firewall-locating TTL walk (default: 20)")
    parser.add_argument("--no-ttl-walk", action="store_true",
                        help="skip the TTL-walk diagnostic on TLS failures")
    parser.add_argument("--include", action="append", default=[],
                        metavar="SUBSTRING",
                        help="only test hosts containing SUBSTRING (repeatable)")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON instead of the text report")
    parser.add_argument("--list", action="store_true",
                        help="print the domains that would be tested, then exit")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colors")
    opts = parser.parse_args(argv)

    targets = build_targets(opts.org_id, opts.cluster_id)
    if opts.include:
        targets = [t for t in targets
                   if any(s.lower() in t["host"].lower() for s in opts.include)]
        if not targets:
            print("No targets match --include filter(s).", file=sys.stderr)
            return 2

    if opts.list:
        for t in targets:
            print("%-50s %-9s %s" % (t["host"], t["kind"], t["label"]))
        return 0

    pal = Palette(sys.stdout.isatty() and not opts.no_color and not opts.json)
    out = sys.stderr if opts.json else sys.stdout

    print("astro-network-check v%s  |  Python %s  |  %s"
          % (VERSION, sys.version.split()[0], time.strftime("%Y-%m-%d %H:%M:%S %Z")),
          file=out)
    print("Testing %d endpoint(s), timeout %.0fs. Redirect targets discovered "
          "along the way are tested too." % (len(targets), opts.timeout), file=out)
    proxies = {k: v for k, v in os.environ.items()
               if k.lower() in ("http_proxy", "https_proxy") and v}
    if proxies:
        print("NOTE: proxy environment variables are set (%s) but this script "
              "tests DIRECT egress, which is what the Astro data plane uses. "
              "If your environment requires a proxy for all egress, failures "
              "below may reflect that policy."
              % ", ".join(sorted(proxies)), file=out)
    print(file=out)

    started = time.monotonic()
    queue = deque(targets)
    tested = {}
    results = []
    try:
        while queue:
            t = queue.popleft()
            if t["host"] in tested:
                continue
            print("  checking %s ..." % t["host"], file=out, flush=True)
            r = check_target(t, opts)
            tested[t["host"]] = r
            results.append(r)
            for d in r["derived"]:
                if d["host"] in tested or any(q["host"] == d["host"] for q in queue):
                    continue
                queue.append({
                    "host": d["host"],
                    "label": "Derived target",
                    "kind": "derived",
                    "paths": [d["path"]],
                    "via": d["why"],
                })
    except KeyboardInterrupt:
        print("\nInterrupted; reporting results so far.", file=out)

    blocked = any(r["status"] == "BLOCKED" for r in results)
    warned = any(r["status"] == "WARN" for r in results)
    exit_code = 1 if blocked else (2 if warned else 0)

    if opts.json:
        print(json.dumps({
            "version": VERSION,
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "org_id": opts.org_id,
            "cluster_id": opts.cluster_id,
            "exit_code": exit_code,
            "results": results,
        }, indent=2))
    else:
        print_report(results, opts, pal, started)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
