package authn_test

import (
	"bytes"
	"crypto/x509"
	"slices"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn"
	"github.com/tkngch/fizzled-go/internal/testpki"
)

// pemBeginMarker opens a PEM block. Spelled out here because the tests read the
// package from the outside.
const pemBeginMarker = "-----BEGIN "

// FuzzTrustBundle holds the trust bundle that NewAuthenticator accepts: the
// file is a sequence of PEM blocks and nothing else, and every one of them is a
// certificate the standard parser keeps. This trust bundle structure contrasts
// with what pem.Decode accepts: pem.Decode scans forward for the next block it
// can read and drops whatever it passed over on the way. So a root of the
// bundle can go missing in silence, to be met at a handshake rather than at
// start-up. TestNewAuthenticatorRejectsBundleFile pins the damage a reader
// thought to write down. This pins the property, over the files nobody did.
func FuzzTrustBundle(f *testing.F) {
	for _, seed := range bundleSeeds(f) {
		f.Add(seed)
	}

	// One file for the whole run, rewritten each iteration. NewAuthenticator
	// reads a path, and a directory per iteration would be millions of them.
	dir := f.TempDir()

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, err := authn.NewAuthenticator(testpki.WriteFile(t, dir, "ca.crt", raw), nil)
		if err != nil {
			// Rejecting is always allowed: this bundle is held to more than
			// the standard parser asks, and the cases it turns away for are
			// TestNewAuthenticatorRejectsBundle's to name.
			return
		}

		requireStandardParserAgrees(t, raw)
	})
}

// requireStandardParserAgrees asserts that x509.CertPool.AppendCertsFromPEM
// finds a certificate in every block of an accepted bundle.
//
// It is the real parser, so this method and the parser cannot drift apart as Go
// changes what it will keep. Taking the blocks one at a time is what makes a
// dropped block visible: run over the whole file, the standard parser reports
// only whether it kept anything at all, which is the silence this whole check
// exists to break.
func requireStandardParserAgrees(t *testing.T, raw []byte) {
	t.Helper()

	if !x509.NewCertPool().AppendCertsFromPEM(raw) {
		t.Fatalf("accepted a bundle the standard parser finds no certificate in")
	}

	for _, block := range bundleBlocks(raw) {
		if !x509.NewCertPool().AppendCertsFromPEM(block) {
			t.Fatalf("accepted a bundle carrying a block the standard parser drops: [%s]", block)
		}
	}
}

// bundleBlocks splits an accepted bundle into the PEM blocks it is made of.
//
// Cutting on the begin marker is sound only because the bundle was accepted:
// the file is expected to have back-to-back blocks with nothing between them,
// each opening with the marker. A marker cannot appear inside a block, because
// the base64 a certificate is written in has no dash in its alphabet.
func bundleBlocks(raw []byte) [][]byte {
	marker := []byte(pemBeginMarker)
	blocks := [][]byte{}

	for chunk := range bytes.SplitSeq(bytes.TrimSpace(raw), marker) {
		if len(chunk) == 0 {
			continue
		}

		blocks = append(blocks, slices.Concat(marker, chunk))
	}

	return blocks
}

// bundleSeeds are the bundle shapes worth starting from: the ones a reader
// thought of, so that the fuzzer can spend its time on the ones nobody did.
// They are built from the same helpers the table-driven bundle tests use, so
// the two cannot come to disagree about what a damaged block looks like.
func bundleSeeds(f *testing.F) [][]byte {
	f.Helper()

	root := certificatePEM(newCertificateAuthority(f))
	other := certificatePEM(newCertificateAuthority(f))

	truncated, _, _ := bytes.Cut(root, []byte("-----END "))

	return [][]byte{
		nil,
		[]byte("not a pem block"),
		root,
		slices.Concat(root, other),
		slices.Concat(root, []byte("garbage\n")),
		slices.Concat([]byte("garbage\n"), root),
		slices.Concat(root, []byte("garbage\n"), other),
		corruptFraming(root),
		corruptBody(f, root),
		withPEMHeader(root),
		slices.Concat(withPEMHeader(root), other),
		truncated,
		[]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
		certificatePEM(newCertificateAuthorityWithURIs(f, "spiffe://"+authn.TrustDomain)),
		certificatePEM(newCertificateAuthorityWithURIs(f, "spiffe://"+authn.TrustDomain+"/ca")),
		certificatePEM(newCertificateAuthorityWithURIs(f, "spiffe://other.internal")),
		certificatePEM(newCertificateAuthorityWithKeyUsage(f, x509.KeyUsageCRLSign)),
	}
}
