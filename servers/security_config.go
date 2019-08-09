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

package servers

import (
	"crypto/tls"

	"github.com/deciphernow/nautls/builders"
	"github.com/pkg/errors"
)

// SecurityConfig provides a serializable representation of a tls.Config structure for servers.
type SecurityConfig struct {

	// Authorities defines the trusted certificate authorities for verifying mTLS clients. The values must be URLs that
	// point to the location of PEM encoded certificates.
	//
	// Note that in addition to those schemes supported by [getter](https://godoc.org/github.com/hashicorp/go-getter) a
	// "base64" scheme is supported for providing the PEM encoded certifiate in the path of the URL directly. This is most
	// applicable when the certificate data must be provided via an environement variable.
	Authorities []string `json:"authorities" mapstructure:"authorities" yaml:"authorities"`

	// Certificate defines the server certificate. The value must be a URL that points to the location of a PEM encoded
	// certificate.
	//
	// Note that in addition to those schemes supported by [getter](https://godoc.org/github.com/hashicorp/go-getter) a
	// "base64" scheme is supported for providing the PEM encoded certifiate in the path of the URL directly. This is most
	// applicable when the certificate data must be provided via an environement variable.
	Certificate string `json:"certificate" mapstructure:"certificate" yaml:"certificate"`

	// Key defines the server key. The value must be a URL that points to the location of a PEM encoded key.
	//
	// Note that in addition to those schemes supported by [getter](https://godoc.org/github.com/hashicorp/go-getter) a
	// "base64" scheme is supported for providing the PEM encoded certifiate in the path of the URL directly. This is most
	// applicable when the certificate data must be provided via an environement variable.
	Key string `json:"key" mapstructure:"key" yaml:"key"`

	// Authentication defines the client authentication mode for mTLS connections.
	//
	// For serialization puposes (i.e., JSON and YAML) the value must be the string representation of a tls.ClientAuthType
	// constant (e.g., "RequireAnyClientCert"). See https://golang.org/pkg/crypto/tls/#ClientAuthType.
	Authentication Authentication `json:"authentication" mapstructure:"authentication" yaml:"authentication"`
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

	config := &tls.Config{
		Certificates: certificates,
		ClientAuth:   tls.ClientAuthType(c.Authentication),
		ClientCAs:    pool,
	}

	return config, nil
}
