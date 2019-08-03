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
	"encoding/json"
	"fmt"
	"strings"

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

// Authentication subtypes tls.ClientAuthType to provide serialization support.
type Authentication tls.ClientAuthType

// MarshalJSON returns a JSON representation of the authentication or an error.
func (a Authentication) MarshalJSON() ([]byte, error) {

	value, err := a.ToString()
	if err != nil {
		return nil, errors.Wrap(err, "error marshalling authentication to json")
	}

	return []byte(value), nil
}

// MarshalYAML returns a YAML representation of the authentication or an error.
func (a Authentication) MarshalYAML() (interface{}, error) {
	return a.ToString()
}

// UnmarshalJSON unmarshals an authentication from JSON or returns an error.
func (a *Authentication) UnmarshalJSON(bytes []byte) error {

	var value string

	err := json.Unmarshal(bytes, &value)
	if err != nil {
		return errors.Wrap(err, "error unmarshalling authentication from json")
	}

	return a.FromString(value)
}

// UnmarshalYAML unmarshals an authentication from YAML or returns an error.
func (a *Authentication) UnmarshalYAML(unmarshal func(interface{}) error) error {

	var value string

	err := unmarshal(&value)
	if err != nil {
		return errors.Wrap(err, "error unmarshalling authentication from yaml")
	}

	return a.FromString(value)
}

// FromString sets the value of an authentication to the value represented by a string or errors.
func (a *Authentication) FromString(value string) error {

	var authentication Authentication

	switch strings.ToLower(value) {
	case "noclientcert":
		authentication = Authentication(tls.NoClientCert)
	case "requestclientcert":
		authentication = Authentication(tls.RequestClientCert)
	case "requireanyclientcert":
		authentication = Authentication(tls.RequireAnyClientCert)
	case "verifyclientcertifgiven":
		authentication = Authentication(tls.VerifyClientCertIfGiven)
	case "requireandverifyclientcert":
		authentication = Authentication(tls.RequireAndVerifyClientCert)
	default:
		return errors.New(fmt.Sprintf("error unmarshalling unknown authentication value [%s]", value))
	}

	*a = authentication

	return nil
}

// ToString returns the string representation of the authentication or an error.
func (a Authentication) ToString() (string, error) {

	switch tls.ClientAuthType(a) {
	case tls.NoClientCert:
		return "NoClientCert", nil
	case tls.RequestClientCert:
		return "RequestClientCert", nil
	case tls.RequireAnyClientCert:
		return "RequireAnyClientCert", nil
	case tls.VerifyClientCertIfGiven:
		return "VerifyClientCertIfGiven", nil
	case tls.RequireAndVerifyClientCert:
		return "RequireAndVerifyClientCert", nil
	default:
		return "", errors.New(fmt.Sprintf("error converting unknown authentication value to string [%d]", a))
	}
}
