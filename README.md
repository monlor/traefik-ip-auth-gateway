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
