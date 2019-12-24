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
	"net/http"

	"github.com/pkg/errors"
)

// ClientBuilder provides an builder for http.Client instances.
type ClientBuilder struct {
	config    ClientConfig
	tlsConfig *tls.Config
	Security  SecurityConfig `json:"security" mapstructure:"security" yaml:"security"`
}

// NewClientBuilder intializes a new instance of the ClientBuilder structure.
func NewClientBuilder() *ClientBuilder {
	return &ClientBuilder{}
}

// Build creates an http.Client from the ClientBuilder.
func (b *ClientBuilder) Build() (*http.Client, error) {
	clientBuild, err := b.config.Build()
	if err != nil {
		return nil, errors.Wrap(err, "error building client")
	}

	//Set order of precedence (tls being most important)

	if b.Security.Build() != nil {
		//Call withSecurityBuilder
	}

	if b.tlsConfig != nil {
		//call withTLS
	}
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

// WithSecurityBuilder provides a builder for tls.Config instances used by the client
func (b *ClientBuilder) WithSecurityBuilder(builder *SecurityBuilder) *ClientBuilder {
	b.config.Security = builder.config
	return b
}

// WithTLS sets the tls configuration of the client
func (b *ClientBuilder) WithTLS(config *tls.Config) *ClientBuilder {
	b.tlsConfig = config
	return b
}
