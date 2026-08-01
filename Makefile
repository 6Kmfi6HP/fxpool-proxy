.PHONY: build test race vet fmt-check cross
build:
	go build -trimpath -o fxpool-proxy ./cmd/fxpool-proxy
test:
	go test ./...
race:
	go test -race ./...
vet:
	go vet ./...
fmt-check:
	@test -z "$$(gofmt -l cmd internal)"
cross:
	GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/fxpool-proxy-linux-amd64 ./cmd/fxpool-proxy
	GOOS=linux GOARCH=arm64 go build -trimpath -o /tmp/fxpool-proxy-linux-arm64 ./cmd/fxpool-proxy
