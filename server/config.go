package server

import (
	"crypto/tls"

	"github.com/deciphernow/nautls/builders"
	"github.com/pkg/errors"
)

// BuildServerTLSConfig creates a TLS config for a server.
func BuildServerTLSConfig(ca, cert, key string) (*tls.Config, error) {
	cfg := tls.Config{}

	//MAKE CERT
	serverCert, err := buildx509Identity(cert, key)
	if err != nil {
		return nil, errors.Wrap(err, "error loading certificates")
	}
	cfg.Certificates = serverCert

	cfg.ClientAuth = tls.RequireAndVerifyClientCert

	var authorities []string
	certPool, err := builders.BuildCertificatePool(authorities)
	if err != nil {
		return nil, errors.Wrap(err, "error building certificates")
	}
	cfg.ClientCAs = certPool

	return &cfg, nil
}

func buildx509Identity(cert string, key string) ([]tls.Certificate, error) {
	theCert := []tls.Certificate{}
	certs, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, errors.Wrap(err, "error loading certificates")
	}
	theCert = append(theCert, certs)
	return theCert, nil
}
