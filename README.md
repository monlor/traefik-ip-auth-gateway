# traefik-ip-auth-gateway

An external `forwardAuth` gateway for Traefik that adds a temporary in-memory allowlist by `host + public IP` in front of an upstream identity provider such as Authelia.

## Behavior

1. Traefik sends each protected request to `auth-gateway`.
2. A Traefik `headers` middleware can inject `X-Auth-Cache-TTL` and `X-Auth-Cache-Key` before `forwardAuth`.
3. `auth-gateway` extracts the real client IP from `X-Forwarded-For`.
4. If `host + cache_key + ip` is still within TTL, it returns `200` immediately.
5. Otherwise it forwards the request to the upstream auth endpoint.
6. If upstream auth succeeds, `auth-gateway` caches the scope using the injected TTL.

## Configuration

Copy [config.example.yml](/Users/monlor/Workspace/traefik-ip-auth-gateway/config.example.yml) to `config.yml` and adjust values.

```yaml
listen_addr: ":8080"
upstream_url: "http://authelia:9091/api/authz/forward-auth"
default_ttl: "2h"
```

- `default_ttl` is optional. If omitted, `auth-gateway` defaults to `2h`.
- `default_ttl` is only the fallback when Traefik does not inject a TTL header.
- Per-service policy should be injected by Traefik, not stored here.
- Cache entries are scoped by `host + cache_key + client_ip`, where `cache_key` is optional.

## Run

```bash
go test ./...
go run ./cmd/traefik-ip-auth-gateway -config config.yml
```

## Traefik With Docker Labels

Define the shared `forwardAuth` middleware once, for example on the `auth-gateway` service:

```yaml
labels:
  - traefik.http.middlewares.auth-forward.forwardauth.address=http://auth-gateway:8080
  - traefik.http.middlewares.auth-forward.forwardauth.trustForwardHeader=true
```

Then define per-service cache policy with a `headers` middleware and chain it before `forwardAuth`:

```yaml
labels:
  - traefik.http.routers.myapp.middlewares=myapp-auth-chain@docker
  - traefik.http.middlewares.myapp-auth-policy.headers.customrequestheaders.X-Auth-Cache-TTL=30m
  - traefik.http.middlewares.myapp-auth-chain.chain.middlewares=myapp-auth-policy,auth-forward
```

- `X-Auth-Cache-TTL` is optional. If omitted, `auth-gateway` uses the default `2h`.
- `X-Auth-Cache-Key` is optional. If omitted, the scope is just the request host.
- Add `X-Auth-Cache-Key` only when multiple services share one host and you need separate cache scopes.

If you do not need a per-service override, you can attach `auth-forward@docker` directly with no extra policy middleware:

```yaml
labels:
  - traefik.http.routers.myapp.middlewares=auth-forward@docker
```

## Traefik File Provider

The same pattern works in a dynamic config file for non-Docker services:

```yaml
http:
  middlewares:
    auth-forward:
      forwardAuth:
        address: "http://auth-gateway:8080"
        trustForwardHeader: true

    api-auth-policy:
      headers:
        customRequestHeaders:
          X-Auth-Cache-TTL: "15m"

    api-auth-chain:
      chain:
        middlewares:
          - api-auth-policy
          - auth-forward
```

Attach `api-auth-chain` to any router, whether the backend service is Docker-managed or an external URL.

If you do not need an override in file-provider mode, attach `auth-forward` directly to the router and rely on the default `2h`.

## Limits

- Cache is in memory only. Restarting the container clears authenticated IPs.
- Running multiple `auth-gateway` replicas will produce independent caches.
- This design improves compatibility with third-party apps that cannot complete OAuth, but it is still weaker than app-specific tokens or mTLS.
