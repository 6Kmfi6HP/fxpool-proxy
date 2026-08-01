.PHONY: build test race vet fmt-check cross
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)
build:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o fxpool-proxy ./cmd/fxpool-proxy
test:
	go test ./...
race:
	go test -race ./...
vet:
	go vet ./...
fmt-check:
	@test -z "$$(gofmt -l cmd internal)"
cross:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o /tmp/fxpool-proxy-linux-amd64 ./cmd/fxpool-proxy
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o /tmp/fxpool-proxy-linux-arm64 ./cmd/fxpool-proxy
