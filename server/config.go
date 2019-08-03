package server

import (
	"crypto/tls"

	"github.com/deciphernow/nautls/builders"
	"github.com/pkg/errors"
)

// Configuration represents a server TLS configuration.
type Configuration struct {

	// Authorities defines the trusted certificate authorities
	Authorities []string `json:"authorities" mapstructure:"authorities" yaml:"authorities"`

	// Certificate defines the server certificate used for TLS connections
	Certificate string `json:"certificate" mapstructure:"certificate" yaml:"certificate"`

	// Key defines the server key used for TLS connections
	Key string `json:"key" mapstructure:"key" yaml:"key"`
}

// Build creates a tls.Config from a Configuration.
func (c *Configuration) Build() (*tls.Config, error) {

	pool, err := builders.BuildCertificatePool(c.Authorities)
	if err != nil {
		return nil, errors.Wrap(err, "error building certificate authority pool")
	}

	serverCert, err := builders.BuildCertificates(c.Certificate, c.Key)
	if err != nil {
		return nil, errors.Wrap(err, "error building certificates")
	}

	config := &tls.Config{
		Certificates: serverCert,
		RootCAs:      pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	return config, nil
}
