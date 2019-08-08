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

package client

import (
	"crypto/tls"

	"github.com/deciphernow/nautls/builders"
	"github.com/pkg/errors"
)

// Configuration represents a client TLS configuration.
type Configuration struct {

	// Authorities defines the trusted certificate authorities.
	Authorities []string `json:"authorities" mapstructure:"authorities" yaml:"authorities"`

	// Certificate defines the client certificate used for mTLS connections.
	Certificate string `json:"certificate" mapstructure:"certificate" yaml:"certificate"`

	// Key defines the client key used for mTLS connections.
	Key string `json:"key" mapstructure:"key" yaml:"key"`

	// Server defines the server name used for verification.
	Server string `json:"server" mapstructure:"server" yaml:"server"`
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
		RootCAs:      pool,
		ServerName:   c.Server,
	}

	return config, nil
}

// WithAuthority sets the trusted certificate authority.
func (c *Configuration) WithAuthority(authority string) *Configuration {
	c.Authorities = []string{authority}
	return c
}

// WithCertificate sets the client certificate used for mTLS connections.
func (c *Configuration) WithCertificate(certificate string) *Configuration {
	c.Certificate = certificate
	return c
}

// WithKey sets the client key used for mTLS connections.
func (c *Configuration) WithKey(key string) *Configuration {
	c.Key = key
	return c
}

// WithServer sets the server name used for verification.
func (c *Configuration) WithServer(server string) *Configuration {
	c.Server = server
	return c
}
