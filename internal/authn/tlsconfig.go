package authn

import "crypto/tls"

// newClientTLSConfig disables Go's own hostname and chain verification, which
// our SVIDs cannot satisfy (no DNS SAN), and installs verify in its place. The
// two are set here, together, so neither can be left without the other.
func newClientTLSConfig(
	identity tls.Certificate,
	verify func(tls.ConnectionState) error,
) *tls.Config {
	config := baseTLSConfig(identity, verify)

	// Disable Go's own hostname and chain verification, which the client side
	// needs because our SVIDs carry no DNS SAN.
	config.InsecureSkipVerify = true

	return config
}

// newServerTLSConfig requires a client certificate and disables session
// tickets, so every connection is a full handshake verified by verify.
func newServerTLSConfig(
	identity tls.Certificate,
	verify func(tls.ConnectionState) error,
) *tls.Config {
	config := baseTLSConfig(identity, verify)
	config.ClientAuth = tls.RequireAnyClientCert
	config.SessionTicketsDisabled = true

	return config
}

// baseTLSConfig carries the transport policy shared by both sides of a
// connection, presenting identity and verifying the peer with verify.
// The fields are spelled out because the exhaustruct linter asks for it.
func baseTLSConfig(
	identity tls.Certificate,
	verify func(tls.ConnectionState) error,
) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{identity},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		Renegotiation:      tls.RenegotiateNever,
		ClientAuth:         tls.NoClientCert,
		VerifyConnection:   verify,
		InsecureSkipVerify: false,

		Rand:                  nil,
		Time:                  nil,
		NameToCertificate:     nil,
		GetCertificate:        nil,
		GetClientCertificate:  nil,
		GetConfigForClient:    nil,
		VerifyPeerCertificate: nil,
		RootCAs:               nil,
		NextProtos:            nil,
		ServerName:            "",
		ClientCAs:             nil,
		// PreferServerCipherSuites is deprecated and ignored, but gosec (G402)
		// requires it to be set.
		PreferServerCipherSuites:            true,
		SessionTicketsDisabled:              false,
		SessionTicketKey:                    [32]byte{},
		ClientSessionCache:                  nil,
		UnwrapSession:                       nil,
		WrapSession:                         nil,
		CurvePreferences:                    nil,
		DynamicRecordSizingDisabled:         false,
		KeyLogWriter:                        nil,
		EncryptedClientHelloConfigList:      nil,
		EncryptedClientHelloRejectionVerify: nil,
		GetEncryptedClientHelloKeys:         nil,
		EncryptedClientHelloKeys:            nil,
	}
}
