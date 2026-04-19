# traefik-ip-auth-gateway

A Traefik HTTP middleware plugin that wraps an upstream `forward-auth` endpoint and caches successful challenges by `middleware + method + host + request URI + public IP`.

It is designed for setups such as Authelia where one browser on one public egress IP should complete the upstream login flow once, and then the same public IP can reuse that authorization until the TTL expires.

## Behavior

1. The plugin receives the protected request directly inside Traefik.
2. If the client IP matches `allowlist`, the request goes straight to the backend.
3. If the current `middleware + method + host + request URI + public IP` grant is still valid, the request goes straight to the backend.
4. Otherwise the plugin calls the configured upstream `forward-auth` endpoint.
5. The first probe for a new public IP strips `Cookie` so an ambient upstream session cannot auto-authorize a brand new IP.
6. If upstream returns `3xx`, `401`, or `403`, the plugin records a short pending challenge window and passes the upstream response back to the client.
7. During that pending window, the next request from the same public IP is allowed to carry `Cookie` to upstream.
8. The first upstream `2xx` during that pending window stores the IP grant for `grantTTL`.

## Config

All business config lives on each middleware instance. There is no separate `config.yml`.

```yaml
address: "http://authelia:9091/api/authz/forward-auth"
grantTTL: "2h"
challengeTTL: "5m"
allowlist:
  - "192.168.31.0/24"
authResponseHeaders:
  - "Remote-User"
  - "Remote-Groups"
```

### Fields

- `address` is required and must be an absolute `http://` or `https://` URL.
- `grantTTL` defaults to `2h`. Set `0s` to disable IP caching and behave like a normal `forward-auth` middleware.
- `challengeTTL` defaults to `5m`.
- `allowlist` accepts single IPs or CIDRs, for both LAN and public IPs.
- `authRequestHeaders` optionally limits which incoming headers are forwarded to upstream. If empty, all non-hop-by-hop request headers are forwarded.
- `authResponseHeaders` copies selected upstream `2xx` response headers into the downstream request before calling the backend.
- `trustForwardHeader` defaults to `false`. When `false`, the plugin derives client IP and scheme from the live request instead of trusting incoming `X-Forwarded-*` headers.
- `preserveLocationHeader` defaults to `false`. When `false`, relative upstream `Location` headers are rewritten onto the auth server origin so redirects behave like Traefik `forwardAuth`.
- `preserveRequestMethod` defaults to `false`. When `false`, upstream auth requests use `GET`.
- `forwardBody` defaults to `false`. When `true`, the request body is buffered and sent to upstream auth and the backend.
- `maxBodySize` defaults to `-1` (unlimited). It is only relevant when `forwardBody=true`.

### Diagnostic Headers

The plugin injects these headers into the downstream request:

- `X-Auth-Cache-Status`: `bypass`, `hit`, or `stored`
- `X-Auth-Cache-Remaining`
- `X-Auth-Cache-Expires-At`

`X-Auth-Cache-Remaining` and `X-Auth-Cache-Expires-At` are only present for `hit` and `stored`.

## Static Plugin Registration

### Remote Plugin

```yaml
experimental:
  plugins:
    ipauth:
      moduleName: github.com/monlor/traefik-ip-auth-gateway
      version: vX.Y.Z
```

Remote loading requires this repository to stay reachable as a public Go module and to publish git tags such as `v0.1.0`. Traefik's plugin catalog also expects the repository to keep:

- a root `.traefik.yml` manifest
- the GitHub topic `traefik-plugin`
- a matching `go.mod` module path

This repository already includes the required manifest in [.traefik.yml](/Users/monlor/Workspace/traefik-ip-auth-gateway/.traefik.yml) and a remote-loading sample in [traefik/static.remote.yml](/Users/monlor/Workspace/traefik-ip-auth-gateway/traefik/static.remote.yml).

### Local Plugin

This repository also includes a local plugin sample in [traefik/static.yml](/Users/monlor/Workspace/traefik-ip-auth-gateway/traefik/static.yml) and [traefik/dynamic.yml](/Users/monlor/Workspace/traefik-ip-auth-gateway/traefik/dynamic.yml).

```yaml
experimental:
  localPlugins:
    ipauth:
      moduleName: github.com/monlor/traefik-ip-auth-gateway
```

Traefik loads local plugins from `./plugins-local/src/...`, so mount this repository there when testing locally.

## Docker Labels

Business config stays on the domain-specific middleware itself:

```yaml
labels:
  - traefik.http.routers.myapp.middlewares=myapp-ip-auth@docker
  - traefik.http.middlewares.myapp-ip-auth.plugin.ipauth.address=http://authelia:9091/api/authz/forward-auth
  - traefik.http.middlewares.myapp-ip-auth.plugin.ipauth.grantTTL=30m
  - traefik.http.middlewares.myapp-ip-auth.plugin.ipauth.challengeTTL=5m
  - traefik.http.middlewares.myapp-ip-auth.plugin.ipauth.allowlist=192.168.31.0/24,203.0.113.7
  - traefik.http.middlewares.myapp-ip-auth.plugin.ipauth.authResponseHeaders=Remote-User,Remote-Groups
  - traefik.http.middlewares.myapp-ip-auth.plugin.ipauth.trustForwardHeader=true
```

## File Provider

```yaml
http:
  middlewares:
    myapp-ip-auth:
      plugin:
        ipauth:
          address: "http://authelia:9091/api/authz/forward-auth"
          grantTTL: "30m"
          challengeTTL: "5m"
          allowlist:
            - "192.168.31.0/24"
            - "203.0.113.7"
          authResponseHeaders:
            - "Remote-User"
            - "Remote-Groups"
          trustForwardHeader: true
```

## Smoke Setup

[docker-compose.example.yml](/Users/monlor/Workspace/traefik-ip-auth-gateway/docker-compose.example.yml) mounts this repository as a local Traefik plugin and attaches the middleware to `whoami`.

```bash
go test ./...
docker compose -f docker-compose.example.yml up
```

[docker-compose.remote.example.yml](/Users/monlor/Workspace/traefik-ip-auth-gateway/docker-compose.remote.example.yml) does the same thing with Traefik remote plugin loading, so no source mount is needed.

The remote example is pinned to the first published plugin tag `v0.1.0` in [traefik/static.remote.yml](/Users/monlor/Workspace/traefik-ip-auth-gateway/traefik/static.remote.yml). Bump that version when you publish a newer release.

```bash
go test ./...
docker compose -f docker-compose.remote.example.yml up
```

## Recommended Authelia Setup

If you are integrating this plugin with Authelia, prefer the modern `ForwardAuth` setup shown in [docker-compose.local-authelia.yml](/Users/monlor/Workspace/traefik-ip-auth-gateway/docker-compose.local-authelia.yml), [traefik/static.local-authelia.yml](/Users/monlor/Workspace/traefik-ip-auth-gateway/traefik/static.local-authelia.yml), [traefik/dynamic.local-authelia.yml](/Users/monlor/Workspace/traefik-ip-auth-gateway/traefik/dynamic.local-authelia.yml), and [authelia/configuration.yml](/Users/monlor/Workspace/traefik-ip-auth-gateway/authelia/configuration.yml).

### Recommended Baseline

- Use Authelia's `http://authelia:9091/api/authz/forward-auth` endpoint, not the legacy `/api/verify` flow, for normal Traefik `ForwardAuth` integrations.
- Configure the Authelia server endpoint explicitly:

```yaml
server:
  endpoints:
    authz:
      forward-auth:
        implementation: ForwardAuth
```

- Put `domain`, `authelia_url`, and `default_redirection_url` under `session.cookies`, not in a global session redirect setting and not as an ad hoc query parameter unless you have a specific reason.

```yaml
session:
  cookies:
    - domain: example.com
      authelia_url: https://auth.example.com
      default_redirection_url: https://app.example.com
```

- Forward the identity headers your backend actually uses. A common set is `Remote-User`, `Remote-Groups`, `Remote-Email`, and `Remote-Name`.
- Keep the middleware definition close to the protected router or service, because the cache scope includes middleware name, method, host, and full request URI.

### Important Caveats

- Only enable `trustForwardHeader=true` when Traefik is the trusted boundary and you have configured Traefik to reject or overwrite client-supplied forwarded headers correctly. If that trust boundary is weak, client IP and scheme can be spoofed.
- This plugin caches by public IP. That is appropriate for NAT-based home or office access flows, but it is not appropriate for high-risk apps where multiple users may share one egress IP and must not reuse each other's successful challenge.
- `grantTTL` is a security tradeoff, not just a performance knob. Longer TTLs reduce auth churn but also extend the window where a previously challenged public IP stays authorized even after upstream logout.
- `challengeTTL` should stay short. It only exists to allow the follow-up request after the user completes the upstream login flow.
- Grants are in-memory and local to a single Traefik instance. Restarts clear them, and multiple replicas do not share them.
- If you run Authelia itself in high-availability mode, use its stateless session storage options rather than the default in-memory behavior. That is separate from this plugin's own per-instance cache behavior.
- Backends must trust identity headers only from Traefik. Do not let clients reach the backend directly with `Remote-User`-style headers.

### Sensible Defaults

- Use `grantTTL=0s` for sensitive admin or operator surfaces where you want standard `ForwardAuth` behavior with no IP reuse.
- Use a short `grantTTL`, for example `5m` to `30m`, for consumer-facing apps where temporary IP reuse is acceptable.
- Keep `preserveLocationHeader=false` for Authelia-style redirect handling unless you know your upstream already emits the exact public URL you want returned to the client.
- Use real subdomains of the same parent domain in production, such as `auth.example.com` and `app.example.com`, so Authelia session cookies and redirects behave predictably.

### Local Development

- For local browser testing, `app.lvh.me` and `auth.lvh.me` are a practical choice because `lvh.me` resolves to `127.0.0.1` without editing `/etc/hosts`.
- Avoid `localhost` as the Authelia cookie domain. Authelia's modern session cookie validation expects a real cookie domain, which means a parent domain with at least one dot or an IP address.
- Expect a certificate warning if you use Traefik's default self-signed cert on `443`.

## Migration From The Old Gateway

- `upstream_url` becomes `address`
- `default_ttl` becomes `grantTTL`
- `bypass_cidrs` becomes `allowlist`
- header-driven `X-Auth-Cache-TTL` and `X-Auth-Cache-Key` are removed
- grants are now scoped by method and full request URI, not just host
- the standalone gateway process is removed; the plugin runs directly inside Traefik

## Limits

- Grants are stored in memory per Traefik instance.
- Restarting Traefik clears cached grants and pending challenges.
- Multiple Traefik replicas do not share grant state.
- Revocation is TTL-based only. Logging out from the upstream IdP does not revoke an existing cached public IP grant before expiry.
