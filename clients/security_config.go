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

	"github.com/deciphernow/nautls/builders"
	"github.com/pkg/errors"
)

// SecurityConfig provides a serializable representation of a tls.Config structure for clients.
type SecurityConfig struct {

	// Authorities defines the trusted certificate authorities. The values must be URLs that point to the location of
	// PEM encoded certificates.
	//
	// Note that in addition to those schemes supported by [getter](https://godoc.org/github.com/hashicorp/go-getter) a
	// "base64" scheme is supported for providing the PEM encoded certifiate in the path of the URL directly. This is most
	// applicable when the certificate data must be provided via an environement variable.
	Authorities []string `json:"authorities" mapstructure:"authorities" yaml:"authorities"`

	// Certificate defines the client certificate used for mTLS connections. The value must be a URL that points to the
	// location of a PEM encoded certificate.
	//
	// Note that in addition to those schemes supported by [getter](https://godoc.org/github.com/hashicorp/go-getter) a
	// "base64" scheme is supported for providing the PEM encoded certifiate in the path of the URL directly. This is most
	// applicable when the certificate data must be provided via an environement variable.
	Certificate string `json:"certificate" mapstructure:"certificate" yaml:"certificate"`

	// Key defines the client key used for mTLS connections. The value must be a URL that points to the location of a PEM
	// encoded key.
	//
	// Note that in addition to those schemes supported by [getter](https://godoc.org/github.com/hashicorp/go-getter) a
	// "base64" scheme is supported for providing the PEM encoded certifiate in the path of the URL directly. This is most
	// applicable when the certificate data must be provided via an environement variable.
	Key string `json:"key" mapstructure:"key" yaml:"key"`

	// Server defines the server name used for certificate verification.
	Server string `json:"server" mapstructure:"server" yaml:"server"`
}

// Build creates a tls.Config from the SecurityConfig instance.
func (c *SecurityConfig) Build() (*tls.Config, error) {

	pool, err := builders.BuildCertificatePool(c.Authorities)
	if err != nil {
		return nil, errors.Wrap(err, "error building certificate authority pool")
	}

	certificates, err := builders.BuildCertificates(c.Certificate, c.Key)
	if err != nil {
		return nil, errors.Wrap(err, "error building certificates")
	}

	configuration := &tls.Config{
		Certificates: certificates,
		RootCAs:      pool,
		ServerName:   c.Server,
	}

	return configuration, nil
}
