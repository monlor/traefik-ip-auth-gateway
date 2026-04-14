FROM golang:1.25-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/traefik-ip-auth-gateway ./cmd/traefik-ip-auth-gateway

FROM alpine:3.22

RUN adduser -D -u 10001 appuser
USER appuser
WORKDIR /app

COPY --from=build /out/traefik-ip-auth-gateway /app/traefik-ip-auth-gateway
COPY config.example.yml /app/config.yml

EXPOSE 8080

ENTRYPOINT ["/app/traefik-ip-auth-gateway"]
CMD ["-config", "/app/config.yml"]
