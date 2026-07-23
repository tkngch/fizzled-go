package authn

import (
	"errors"
	"fmt"

	"github.com/tkngch/fizzled-go/internal/authn/x509svid"
)

// TrustDomain is the trust-domain of this app: fizzled.
const TrustDomain = "fizzled.internal"

var (
	// ErrWrongTrustDomain indicates that the trust-domain of SPIFFE ID is not
	// "fizzled.internal".
	ErrWrongTrustDomain = errors.New("wrong trust domain")

	// ErrUnexpectedIdentity indicates that the path components in SPIFFE ID do
	// not match server or client components.
	ErrUnexpectedIdentity = errors.New("unexpected identity")
)

// AgentIDFromSVID asserts svid is a fizzled client identity and returns its
// agent identifier.
func AgentIDFromSVID(svid x509svid.Leaf) (AgentID, error) {
	if svid.ID().TrustDomain() != TrustDomain {
		return "", fmt.Errorf("agentID from svid: %w", ErrWrongTrustDomain)
	}

	components := svid.ID().PathComponents()
	if len(components) != 3 || components[0] != "client" || components[1] != "agent" {
		return "", fmt.Errorf("agentID from svid: %w", ErrUnexpectedIdentity)
	}

	agentID := AgentID(components[2])

	err := agentID.Validate()
	if err != nil {
		return "", fmt.Errorf("agentID from svid: %w", err)
	}

	return agentID, nil
}

// ValidateServerSVID asserts svid is the fizzled server identity.
func ValidateServerSVID(svid x509svid.Leaf) error {
	if svid.ID().TrustDomain() != TrustDomain {
		return fmt.Errorf("validate server svid: %w", ErrWrongTrustDomain)
	}

	components := svid.ID().PathComponents()
	if len(components) != 1 || components[0] != "server" {
		return fmt.Errorf("validate server svid: %w", ErrUnexpectedIdentity)
	}

	return nil
}
