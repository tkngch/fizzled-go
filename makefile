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
