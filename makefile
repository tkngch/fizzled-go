default: format vet lint test

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

