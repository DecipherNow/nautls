# NauTLS

[![CircleCI](https://circleci.com/gh/DecipherNow/nautls.svg?style=svg)](https://circleci.com/gh/DecipherNow/nautls)
[![Maintainability](https://api.codeclimate.com/v1/badges/c6d23b8f02b1d4c634bf/maintainability)](https://codeclimate.com/github/DecipherNow/nautls/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/c6d23b8f02b1d4c634bf/test_coverage)](https://codeclimate.com/github/DecipherNow/nautls/test_coverage)

NauTLS is a library of utility functions and structs that make working with Transport Layer Security (TLS) in Go a bit more intuitive and flexible.

## Usage

NauTLS requires a Go version with [Modules](https://github.com/golang/go/wiki/Modules) support and uses import versioning so ensure you are using a version of Go that supports Modules and initialize your module.

### General

One of the key features of NauTLS is the use of URLs to define resources that contain TLS cryptographic materials (i.e., certificates and keys). This choice was made as it provides a great deal of flexibility in how these resources are provided. In most cases, the cryptographic material will be on the local filesystem and can be referenced via the absolute path using the `file` scheme (e.g., `file:///etc/tls/client.crt`).  This capability is derived from [Hashicorp](https://www.hashicorp.com/) [go-getter](https://github.com/hashicorp/go-getter).  As a result, any URL scheme supported by that library should be supported.

To support the ability to fetch cryptographic materials from environment variables, NauTLS also supports a custom scheme that allows for the resources to be defined within the URL path component directly.  To utilize this scheme Base64 encode then URL path escape (e.g., [url.PathEscape](https://golang.org/pkg/net/url/#PathEscape)) the resource and append it to the a `base64` schemed URL (e.g., `base64:///UkFORE9NCg==`).

Additionally, all NauTLS configuration structures are tagged with appropriate metadata to support direct serialization using JSON and YAML. Further, they include [mapstructure](https://github.com/mitchellh/mapstructure) tags that allow serialization and deserialization from `map[string]interface{}` instances in Go. While this alone can be helpful when passing configuration objects around in a type unsafe manner, it is primarily done to support definition of these configurations via configuration files using [Viper](https://github.com/spf13/viper) and, by extension, command line options using [Cobra](https://github.com/spf13/cobra).

### Clients

NauTLS provides both configuration and builder patterns for generating [http.Client](https://golang.org/pkg/net/http/#Client) instances suitable for communicating with non-TLS, TLS and mTLS servers.

#### Client via Configuration

The following snippet demonstrates initializing an `http.Client` instance directly from a JSON configuration.

```go
package main

import (
	"encoding/json"

	"github.com/deciphernow/nautls/clients"
)

func main() {

	bytes := []byte(`
	{
		"host": "localhost",
		"port": 443,
		"security": {
			"authorities": ["file:///etc/tls/ca.crt"],
			"certificate": "file:///etc/tls/client.crt",
			"key": "file:///etc/tls/client.key",
			"server": "localhost"
	}
	`)

	var config clients.ClientConfig

	json.Unmarshal(bytes, &config)

	client, _ := config.Build()

}
```

Note the following behaviors of the above code snippet:

- If the `authorities` field is omitted or empty the system certificates returned by [x509.SystemCertPool](https://golang.org/pkg/crypto/x509/#SystemCertPool) will be used to verify the server's certificate.
- If the `certificate` and `key` fields are omitted client certificates will not be provided to the server.
- If the `server` field is omitted the `host` field must match the subject or a subject alternative name of the server's certificate.

#### Client via Builder

The following snippet demonstrates initializing an `http.Client` instance directly using the builder pattern.

```go
package main

import (
	"encoding/json"

	"github.com/deciphernow/nautls/clients"
)

func main() {

	security, _ := clients.NewSecurityBuilder().
		WithAuthorities([]string{"file:///etc/tls/ca.crt"}).
		WithCertificate("file:///etc/tls/client.crt").
		WithKey("file:///etc/tls/client.key").
		WithServer("localhost").
		Build()

	client, _ := clients.NewClientBuilder().
		WithHost("localhost").
		WithPort("443").
		WithTLS(security).
		Build()

}
```

Note the following behaviors of the above code snippet:

- If `WithAuthorities` is not invoked or is invoked with an empty array the system certificates returned by [x509.SystemCertPool](https://golang.org/pkg/crypto/x509/#SystemCertPool) will be used to verify the server's certificate.
- If `WithCertificate` and `WithKey` is not invoked client certificates will not be provided to the server.
- If `WithServer` is not invoked the value provided to `WithHost` in the client configuration must match the subject or a subject alternative name of the server's certificate.
