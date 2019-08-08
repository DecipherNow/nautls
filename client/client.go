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
