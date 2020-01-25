// Copyright 2019 Decipher Technology Studios
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clients

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/deciphernow/acert/encoding"
)

// ClientBuilder provides an builder for http.Client instances.
type ClientBuilder struct {
	config ClientConfig
}

// NewClientBuilder intializes a new instance of the ClientBuilder structure.
func NewClientBuilder() *ClientBuilder {
	return &ClientBuilder{}
}

// Build creates an http.Client from the ClientBuilder.
func (b *ClientBuilder) Build() (*http.Client, error) {
	return b.config.Build()
}

// WithHost sets the hostname or address of the client.
func (b *ClientBuilder) WithHost(host string) *ClientBuilder {
	b.config.Host = host
	return b
}

// WithPort sets the port of the client.
func (b *ClientBuilder) WithPort(port int) *ClientBuilder {
	b.config.Port = port
	return b
}

// WithSecurity sets the TLS configuration of the client.
func (b *ClientBuilder) WithSecurity(security SecurityConfig) *ClientBuilder {
	b.config.Security = security
	return b
}

// WithSecurityBuilder sets the TLS configuration of the client from a SecurityBuilder.
func (b *ClientBuilder) WithSecurityBuilder(builder *SecurityBuilder) *ClientBuilder {
	b.config.Security = builder.config
	return b
}

// WithTLS sets the TLS configuration of the client to a tls.Config. Takes precedence over WithSecurityBuilder.
func (b *ClientBuilder) WithTLS(config *tls.Config) *ClientBuilder {
	b.config.config = config

	// parse each cert into an x509.Certificate so encoding can handle them
	x509Certs := make([]*x509.Certificate, len(config.Certificates[0].Certificate))
	var err error
	for index, certificate := range config.Certificates[0].Certificate {
		x509Certs[index], err = x509.ParseCertificate(certificate)
		if err != nil {

		}
	}

	// ? is the config.PrivateKey what needs to be converted into the SecurityConfig.Key?

	// config.RootCAs is a x509.CertPool, needs to become SecurityConfig.Authorities
	// ! x509.CertPool has no method to export the certs

	b.config.Security = SecurityConfig{
		Certificate: fmt.Sprintf("base64:///%s", encoding.ConfigEncodeCertificates(x509Certs)),
		Server:      config.ServerName,
	}

	return b
}
