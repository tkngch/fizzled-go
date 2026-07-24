package authn_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/tkngch/fizzled-go/internal/authn"
	"github.com/tkngch/fizzled-go/internal/authn/x509svid"
)

func TestAgentIDFromSVID(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		uri             string
		expectedAgentID authn.AgentID
		expectedError   error
	}{
		{
			name:            "valid client identity",
			uri:             "spiffe://" + authn.TrustDomain + "/client/agent/smith",
			expectedAgentID: authn.AgentID("smith"),
			expectedError:   nil,
		},
		{
			name:            "wrong trust domain",
			uri:             "spiffe://evil.internal/client/agent/smith",
			expectedAgentID: "",
			expectedError:   authn.ErrWrongTrustDomain,
		},
		{
			name:            "server identity is not a client",
			uri:             "spiffe://" + authn.TrustDomain + "/server",
			expectedAgentID: "",
			expectedError:   authn.ErrUnexpectedIdentity,
		},
		{
			name:            "unexpected path prefix",
			uri:             "spiffe://" + authn.TrustDomain + "/workload/agent/smith",
			expectedAgentID: "",
			expectedError:   authn.ErrUnexpectedIdentity,
		},
		{
			name:            "agent id carries a dot",
			uri:             "spiffe://" + authn.TrustDomain + "/client/agent/smith.jr",
			expectedAgentID: "",
			expectedError:   authn.ErrInvalidAgentID,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				svid := newSVID(t, testCase.uri)

				agentID, err := authn.AgentIDFromSVID(svid)
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected error [%v], got [%v]", testCase.expectedError, err)
				}

				if agentID != testCase.expectedAgentID {
					t.Errorf("expected id [%s], got [%s]", testCase.expectedAgentID, agentID)
				}
			},
		)
	}
}

func TestValidateServerSVID(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		uri     string
		wantErr error
	}{
		{
			name:    "valid server identity",
			uri:     "spiffe://" + authn.TrustDomain + "/server",
			wantErr: nil,
		},
		{
			name:    "wrong trust domain",
			uri:     "spiffe://evil.internal/server",
			wantErr: authn.ErrWrongTrustDomain,
		},
		{
			name:    "client identity is not the server",
			uri:     "spiffe://" + authn.TrustDomain + "/client/agent/smith",
			wantErr: authn.ErrUnexpectedIdentity,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				svid := newSVID(t, testCase.uri)

				err := authn.ValidateServerSVID(svid)
				if !errors.Is(err, testCase.wantErr) {
					t.Fatalf("expected [%v], got [%v]", testCase.wantErr, err)
				}
			},
		)
	}
}

// newSVID builds a verified X.509-SVID leaf whose single URI SAN is uri, signed
// by a fresh CA that the returned leaf was validated against.
func newSVID(t *testing.T, uri string) x509svid.Leaf {
	t.Helper()

	caCertificate, caKey := newCA(t)
	leafDER := newLeaf(t, caCertificate, caKey, uri)

	bundle := x509.NewCertPool()
	bundle.AddCert(caCertificate)

	leaf, err := x509svid.NewLeaf(bundle, [][]byte{leafDER})
	if err != nil {
		t.Fatalf("new leaf: %v", err)
	}

	return leaf
}

// newLeaf issues a conformant X.509-SVID leaf carrying uri, signed by the CA.
func newLeaf(
	t *testing.T,
	caCertificate *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	uri string,
) []byte {
	t.Helper()

	parsedURI, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse uri [%s]: %v", uri, err)
	}

	key := ecdsaKey(t)

	template := newTemplate(t)
	template.Subject.CommonName = "test leaf"
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(time.Hour)
	template.KeyUsage = x509.KeyUsageDigitalSignature
	template.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
	}
	template.URIs = []*url.URL{parsedURI}

	der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}

	return der
}
