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
	"fmt"
	"net"
	"net/http"

	"github.com/pkg/errors"
)

// ClientConfig provides a serializable representation of an http.Client structure.
type ClientConfig struct {

	// Host defines the hostname or address of the servert to which the client connects.
	Host string `json:"host" mapstructure:"host" yaml:"host"`

	// Port defines the port on the server to which the client connects.
	Port int `json:"port" mapstructure:"port" yaml:"port"`

	// Security defines the TLS configuration used by the client.
	Security SecurityConfig `json:"security" mapstructure:"security" yaml:"security"`
}

// Build creates an http.Client from the ClientConfig instance.
func (c *ClientConfig) Build() (*http.Client, error) {

	configuration, err := c.Security.Build()
	if err != nil {
		return nil, errors.Wrap(err, "error building tls configuration for client")
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, address string) (net.Conn, error) {
				return tls.Dial("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port), configuration)
			},
		},
	}

	return client, nil
}
