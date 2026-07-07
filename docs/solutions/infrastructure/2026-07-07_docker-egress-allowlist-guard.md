# ABOUTME: How to confine untrusted containers to an allowlisted set of egress hosts
# ABOUTME: Internal Docker network + squid CONNECT proxy, fail-closed, allowlist-change aware

# Problem

Containers that hold live credentials (API keys, mounted auth volumes) while
processing untrusted input (here: LLM reviewers reading attacker-controlled
diffs) can be steered by prompt injection into exfiltrating those secrets over
the network. Read-only mounts protect the host filesystem but do nothing about
egress. We needed the reviewers to reach only their model APIs and nothing
else.

# Solution

Two pieces: an internal (no default route) Docker network, and an allowlisting
squid proxy that is the only path out.

```python
EGRESS_NETWORK = "advanced-review-egress"
EGRESS_PROXY_NAME = "advanced-review-proxy"
EGRESS_ALLOWED_HOSTS = (
    "api.anthropic.com", "statsig.anthropic.com", "console.anthropic.com",
    "generativelanguage.googleapis.com", "oauth2.googleapis.com",
    "api.deepseek.com",
)  # exact hosts only, never a leading-dot wildcard

def _squid_conf() -> str:
    hosts = " ".join(EGRESS_ALLOWED_HOSTS)
    return (
        "http_port 3128\n"
        f"acl allowed dstdomain {hosts}\n"
        "acl SSL_ports port 443\n"
        "acl CONNECT method CONNECT\n"
        "http_access deny CONNECT !SSL_ports\n"
        "http_access allow allowed\n"
        "http_access deny all\n"
    )
```

`ensure_egress_guard()` is idempotent and **fails closed**: create the network
`--internal` if missing, write the conf, recreate the proxy container iff the
conf changed (squid reads its config only at start), and if any step fails
return False so the caller aborts (never silently run open-network). The
reviewer containers then join with:

```
docker run --rm -i \
  --network advanced-review-egress \
  -e HTTPS_PROXY=http://advanced-review-proxy:3128 \
  -e HTTP_PROXY=http://advanced-review-proxy:3128 \
  -e NO_PROXY=localhost,127.0.0.1 \
  ...
```

Verified empirically: allowed host -> TLS CONNECT established; disallowed host
-> proxy 403; no proxy on the internal network -> DNS does not even resolve.

# Why It Works

The internal network removes the default route, so the only reachable next hop
is the proxy. squid terminates the client's CONNECT and enforces
`dstdomain` against an exact-host allowlist before opening the upstream
tunnel, so a container cannot reach any host the operator did not name.
`dstdomain` with a leading dot (`.googleapis.com`) is a wildcard that would
match `storage.googleapis.com` and reopen exfiltration; exact hosts avoid
that. Fail-closed setup guarantees the protection is present whenever the flag
that disables it is absent.
