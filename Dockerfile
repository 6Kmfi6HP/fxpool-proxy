# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src

COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/fxpool-proxy ./cmd/fxpool-proxy

FROM alpine:3.22
LABEL org.opencontainers.image.source="https://github.com/6Kmfi6HP/fxpool-proxy" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.description="Firefox IP Protection SOCKS5 and HTTP proxy pool"
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 65532 fxpool \
    && adduser -S -D -H -u 65532 -G fxpool fxpool \
    && install -d -o fxpool -g fxpool -m 0700 /var/lib/fxpool
COPY --from=build /out/fxpool-proxy /usr/local/bin/fxpool-proxy

USER fxpool:fxpool
WORKDIR /var/lib/fxpool
VOLUME ["/var/lib/fxpool"]
EXPOSE 1090 8080
ENV FXPOOL_BIND=0.0.0.0
ENTRYPOINT ["fxpool-proxy"]
CMD ["run", "--root", "/var/lib/fxpool"]
