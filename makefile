default: proto format vet lint test

.PHONY: format
format:
	golangci-lint fmt ./...
	golangci-lint run --fix ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: lint
lint:
	gofmt -l .
	golangci-lint run ./...

.PHONY: test
test:
	go test -cover -race -timeout 30s ./...

.PHONY: fuzz
fuzz:
	go test -run '^$$' -fuzz FuzzAgentID -fuzztime 30s ./internal/authn/
	go test -run '^$$' -fuzz FuzzParse -fuzztime 30s ./internal/authn/spiffeid/
	go test -run '^$$' -fuzz FuzzTrustBundle -fuzztime 30s ./internal/authn/
	go test -run '^$$' -fuzz FuzzVerifyLeafURI -fuzztime 30s ./internal/authn/x509svid/

# The protoc plugins are pinned in go.mod through its `tool` directive, so this
# is the only unpinned input left to generation. Must match the buf version in
# .github/workflows/ci.yml.
BUF_VERSION := 1.72.0

.PHONY: proto
proto:
	@if ! command -v buf > /dev/null 2>&1; then \
		echo "makefile: buf $(BUF_VERSION) required, but buf is not on the PATH."; \
		echo "makefile: see https://buf.build/docs/installation to install it."; \
		exit 1; \
	fi; \
	found=$$(buf --version); \
	if [ "$$found" != "$(BUF_VERSION)" ]; then \
		echo "makefile: buf $(BUF_VERSION) required, found $$found"; \
		exit 1; \
	fi
	buf format -w
	buf lint
	buf generate
