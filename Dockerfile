# syntax=docker/dockerfile:1.7

FROM golang:1.24-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/ldap-proxy ./cmd/ldap-proxy

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/ldap-proxy /ldap-proxy

USER nonroot:nonroot
EXPOSE 3389

HEALTHCHECK --interval=30s --timeout=3s --start-period=3s --retries=3 \
    CMD ["/ldap-proxy", "healthcheck"]

ENTRYPOINT ["/ldap-proxy"]
