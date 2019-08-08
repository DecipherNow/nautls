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

package server

import (
	"crypto/tls"

	"github.com/deciphernow/nautls/builders"
	"github.com/pkg/errors"
)

// Configuration represents a server TLS configuration.
type Configuration struct {

	// Authorities defines the trusted certificate authorities for mTLS connections.
	Authorities []string `json:"authorities" mapstructure:"authorities" yaml:"authorities"`

	// Certificate defines the certificate used for TLS connections.
	Certificate string `json:"certificate" mapstructure:"certificate" yaml:"certificate"`

	// Key defines the server key used for TLS connections.
	Key string `json:"key" mapstructure:"key" yaml:"key"`

	// Mode defines the client verification mode for mTLS connections.
	Authentication Authentication `json:"authentication" mapstructure:"authentication" yaml:"authentication"`
}

// Build creates a tls.Config from a Configuration.
func (c *Configuration) Build() (*tls.Config, error) {

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
