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

// Package client contains structures and functions for building HTTP(S) clients.
//
// Deprecated: The structures and functions in the nautls/client package have been deprecated in favor of the
// implementations found within the nautls/clients package.
package client

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/pkg/errors"
)

// Client represents a client configuration (with or without TLS).
type Client struct {

	// Host defines the hostname or address of the client.
	Host string `json:"host" mapstructure:"host" yaml:"host"`

	// Port defines the port for the client.
	Port int `json:"port" mapstructure:"port" yaml:"port"`

	// TLS defines the TLS configuration for the client.
	TLS Configuration `json:"tls" mapstructure:"tls" yaml:"tls"`
}

// Build creates an http.Client from a Client.
func (c *Client) Build() (*http.Client, error) {

	configuration, err := c.TLS.Build()
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

// WithHost sets the hostname or address of the client.
func (c *Client) WithHost(host string) *Client {
	c.Host = host
	return c
}

// WithPort sets the port of the client.
func (c *Client) WithPort(port int) *Client {
	c.Port = port
	return c
}

// WithTLS sets the TLS configuration of the client.
func (c *Client) WithTLS(tls Configuration) *Client {
	c.TLS = tls
	return c
}
