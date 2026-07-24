package x509svid

import (
	"crypto/x509"
	"fmt"
	"time"
)

// skew is the clock-skew tolerance applied when checking certificate validity,
// so minor clock differences between agent and server do not spuriously reject
// otherwise-valid certificates (README Authentication).
const skew = 2 * time.Minute

// verify cryptographically verifies a peer's raw certificate chain against the
// trust bundle. It anchors the chain to bundle (with a clock-skew tolerance,
// and skipping hostname verification), then runs the SPIFFE X509-SVID
// structural checks. It does NOT assert an identity.
func verify(bundle *x509.CertPool, certificates []*x509.Certificate) error {
	if len(certificates) == 0 {
		return fmt.Errorf("verify: %w", ErrNoCertificate)
	}

	leaf := certificates[0]

	intermediates := x509.NewCertPool()
	for _, intermediate := range certificates[1:] {
		intermediates.AddCert(intermediate)
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:                   "", // hostname verification is skipped.
		Roots:                     bundle,
		Intermediates:             intermediates,
		CurrentTime:               clampToValidity(time.Now(), leaf.NotBefore, leaf.NotAfter, skew),
		KeyUsages:                 []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		MaxConstraintComparisions: 0,
		CertificatePolicies:       []x509.OID{},
	})
	if err != nil {
		return fmt.Errorf("verify [serial %x]: %w", leaf.SerialNumber, err)
	}

	return nil
}

// clampToValidity clamps now into [notBefore, notAfter] when now is within skew
// of a boundary; beyond skew it returns now unchanged and lets Verify reject.
func clampToValidity(now, notBefore, notAfter time.Time, skew time.Duration) time.Time {
	switch {
	case now.Before(notBefore) && !now.Before(notBefore.Add(-skew)):
		return notBefore
	case now.After(notAfter) && !now.After(notAfter.Add(skew)):
		return notAfter
	default:
		return now
	}
}
