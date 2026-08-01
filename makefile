.DELETE_ON_ERROR:

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

.PHONY: build
build:
	go build -o bin/ ./cmd/...

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

.PHONY: secrets
secrets: .secrets/ca.crt \
	.secrets/server.crt .secrets/server-private.key \
	.secrets/agent-smith.crt .secrets/agent-smith-private.key \
	.secrets/agent-jones.crt .secrets/agent-jones-private.key \
	.secrets/roles.json

.PHONY: clean-secrets
clean-secrets:
	rm -rf .secrets

# List the certificates that are expiring within a day (86,400 seconds). The
# list includes unreadable certificates. The listed certificates are reissued.
EXPIRING_CERTS := $(shell for certificate in $(wildcard .secrets/*.crt); do \
	openssl x509 -in "$$certificate" -noout \
		-checkend 86400 > /dev/null 2>&1 \
		|| echo "$$certificate"; \
	done)

# force is never up to date, so naming it as a prerequisite is what marks those
# certificates as needing reissuing.
.PHONY: force
force:

$(EXPIRING_CERTS): force


# 0700, because everything under it is a secret and one of them is the CA key.
# Every rule below takes this as an order-only prerequisite: the directory has
# to exist first, but its mtime changes as files land in it, and that must not
# make the certificates already in it look out of date.
.secrets:
	mkdir -m 700 $@

# Unlike buf, no particular openssl version is pinned. What is required is the
# `x509 -ext` option the leaf rule reads the issued extensions back with.
.PHONY: check-openssl
check-openssl:
	@if ! command -v openssl > /dev/null 2>&1; then \
		echo "makefile: openssl required, but openssl is not on the PATH."; \
		echo "makefile: see https://openssl-library.org/source/ to install it."; \
		exit 1; \
	fi
	@if ! openssl x509 -help 2>&1 | grep -q -- '-ext '; then \
		echo "makefile: openssl without 'x509 -ext' found: $$(openssl version)."; \
		echo "makefile: OpenSSL 1.1.1 or newer required. The LibreSSL that macOS"; \
		echo "makefile: ships as /usr/bin/openssl is not enough."; \
		echo "makefile: see https://openssl-library.org/source/ to install it."; \
		exit 1; \
	fi

# umask, rather than a chmod after the fact, so the key is never even briefly
# world-readable.
.secrets/%-private.key: | .secrets check-openssl
	umask 077 && openssl genpkey -algorithm EC \
		-pkeyopt ec_paramgen_curve:P-256 -out $@

# The URI SAN is what binds the root to the trust domain. Without it the root
# carries no SPIFFE ID, and the trust-domain checks the code implements against
# a signing certificate have nothing to compare and pass vacuously.
.secrets/ca.crt: .secrets/ca-private.key | .secrets check-openssl
	openssl req -x509 -new -key $< -sha256 -days 1825 \
		-subj "/CN=fizzled.internal local CA" \
		-addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
		-addext "keyUsage=critical,keyCertSign,cRLSign" \
		-addext "subjectAltName=URI:spiffe://fizzled.internal" \
		-addext "subjectKeyIdentifier=hash" \
		-out $@

.INTERMEDIATE: .secrets/server.ext
.secrets/server.ext: | .secrets
	@printf '%s\n' \
		'basicConstraints       = critical, CA:FALSE' \
		'keyUsage               = critical, digitalSignature' \
		'extendedKeyUsage       = critical, serverAuth, clientAuth' \
		'subjectAltName         = critical, URI:spiffe://fizzled.internal/server' \
		'subjectKeyIdentifier   = hash' \
		'authorityKeyIdentifier = keyid' > $@

.secrets/agent-%.ext: | .secrets
	@printf '%s\n' \
		'basicConstraints       = critical, CA:FALSE' \
		'keyUsage               = critical, digitalSignature' \
		'extendedKeyUsage       = critical, serverAuth, clientAuth' \
		'subjectAltName         = critical, URI:spiffe://fizzled.internal/client/agent/$*' \
		'subjectKeyIdentifier   = hash' \
		'authorityKeyIdentifier = keyid' > $@

.secrets/%.csr: .secrets/%-private.key | .secrets check-openssl
	openssl req -new -key $< -subj "/" -out $@

# The prerequisites are picked out by name rather than by position, so that
# adding or reordering one cannot quietly hand openssl the wrong file.
#
# The two calls after the issuance are checks rather than outputs: the first
# verifies the new certificate against the bundle it has to anchor to, and the
# second prints the four extensions the issuance policy is written in terms of,
# so they can be read back off a real certificate.
.secrets/%.crt: .secrets/%.csr .secrets/ca.crt .secrets/ca-private.key .secrets/%.ext | .secrets check-openssl
	openssl x509 -req \
		-in $< \
		-CA $(filter %/ca.crt,$^) \
		-CAkey $(filter %/ca-private.key,$^) \
		-extfile $(filter %.ext,$^) \
		-set_serial 0x$$(openssl rand -hex 16) \
		-days 7 -sha256 \
		-out $@
	openssl verify -CAfile $(filter %/ca.crt,$^) $@
	openssl x509 -in $@ -noout \
		-ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName

.secrets/roles.json: | .secrets
	@printf '%s\n' '{"jones":"USER","smith":"USER"}' > $@

