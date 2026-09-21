# syntax=docker/dockerfile:1.7

# Must satisfy the go directive in go.mod, which is 1.25.0. The floor used to be
# 1.23, set by google.golang.org/protobuf 1.36 which the generated Nexus contract
# in proto/nexus/v1 requires; it moved for the github.com/TrueOpen/wire
# import, because wire's own go.mod declares 1.25.0 and `go mod tidy` on an older
# toolchain rewrites the directive anyway.
FROM golang:1.25-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cortexd ./cmd/cortexd && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cortexctl ./cmd/cortexctl

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S cortex && adduser -S -G cortex cortex && \
    mkdir -p /etc/cortex /var/lib/cortex/evidence /var/run/cortex && \
    chown -R cortex:cortex /etc/cortex /var/lib/cortex /var/run/cortex
COPY --from=build /out/cortexd /out/cortexctl /usr/local/bin/
USER cortex
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/cortexd"]
CMD ["-config", "/etc/cortex/config.yaml"]
