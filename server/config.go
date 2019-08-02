package server

import (
	"crypto/tls"

	"github.com/deciphernow/nautls/builders"
	"github.com/pkg/errors"
)

// BuildServerTLSConfig creates a TLS config for a server.
func BuildServerTLSConfig(ca, cert, key string) (*tls.Config, error) {
	cfg := tls.Config{}

	//build server certificate and assign to tls config
	serverCert, err := buildx509Identity(cert, key)
	if err != nil {
		return nil, errors.Wrap(err, "error loading certificates")
	}
	cfg.Certificates = serverCert

	//assign client auth to tls config
	cfg.ClientAuth = tls.RequireAndVerifyClientCert

	//build cert pool and assign to tls config
	var authorities []string
	certPool, err := builders.BuildCertificatePool(authorities)
	if err != nil {
		return nil, errors.Wrap(err, "error building certificates")
	}
	cfg.ClientCAs = certPool

	return &cfg, nil
}

//build tls certificate with cert and key
func buildx509Identity(cert string, key string) ([]tls.Certificate, error) {
	theCert := []tls.Certificate{}
	certs, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, errors.Wrap(err, "error loading certificates")
	}
	theCert = append(theCert, certs)
	return theCert, nil
}

//Have listener?
//https://gist.github.com/spikebike/2232102
