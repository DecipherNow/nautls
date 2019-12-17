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

package identities

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"

	"github.com/deciphernow/nautls/internal/urls"
	"github.com/pkg/errors"
)

// IdentityConfig provides a serializable representation of an Identity structure.
type IdentityConfig struct {
	Authorities string `json:"authorities" mapstructure:"authorities" yaml:"authorities"`
	Certificate string `json:"certificate" mapstructure:"certificate" yaml:"certificate"`
	Key         string `json:"key" mapstructure:"key" yaml:"key"`
}

// Build creates an Identity from the IdentityConfig instance.
func (c *IdentityConfig) Build() (*Identity, error) {

	authorities, err := loadCertificates(c.Authorities)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading authorities from [%s]", c.Authorities)
	}

	certificate, err := loadCertificate(c.Certificate)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading certificate from [%s]", c.Certificate)
	}

	key, err := loadKey(c.Key)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading key from [%s]", c.Key)
	}

<<<<<<< HEAD
	identity := &Identity{
		authorities: authorities,
		certificate: certificate,
		key:         key,
	}
=======
	identity := NewIdentity(authorities, certificate, key)
>>>>>>> f6d8f1ebbfb4d123ec42f777d95be247af21e671

	return identity, nil
}

// loadCertificate loads a single PEM encoded X.509 certificate from a URL. Note that an error is thrown if the number
// of certificates decoded is not one.
func loadCertificate(resource string) (*x509.Certificate, error) {

	certificates, err := loadCertificates(resource)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading certificate from [%s]", resource)
	}

	switch len(certificates) {
	case 0:
		return nil, fmt.Errorf("no certificates defined in [%s]", resource)
	case 1:
		return certificates[0], nil
	default:
		return nil, fmt.Errorf("multiple certificates defined in [%s]", resource)
	}
}

// loadCertificates loads PEM encoded X.509 certificates from a URL.
func loadCertificates(resource string) ([]*x509.Certificate, error) {

	bytes, err := loadResource(resource)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading certificates from [%s]", resource)
	}

	certificates, err := decodeCertificates(bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "error decoding certificates from [%s]", resource)
	}

	return certificates, nil
}

// loadKey loads a single PEM encoded RSA key from a URL. Note that an error is thrown if the number
// of keys decoded is not one.
func loadKey(resource string) (*rsa.PrivateKey, error) {

	keys, err := loadKeys(resource)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading key from [%s]", resource)
	}

	switch len(keys) {
	case 0:
		return nil, fmt.Errorf("no keys defined in [%s]", resource)
	case 1:
		return keys[0], nil
	default:
		return nil, fmt.Errorf("multiple keys defined in [%s]", resource)
	}
}

// loadCertificates loads PEM encoded RSA Keys from a URL.
func loadKeys(resource string) ([]*rsa.PrivateKey, error) {

	bytes, err := loadResource(resource)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading keys from [%s]", resource)
	}

	keys, err := decodeKeys(bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "error decoding keys from [%s]", resource)
	}

	return keys, nil

}

// decodeCertificates decodes PEM encoded X.509 certificates. Note that unparsable values outside a PEM block are
// ignored while unparsable values inside a PEM block will result in an error.
func decodeCertificates(bytes []byte) ([]*x509.Certificate, error) {

	var result []*x509.Certificate

	decoded, tail := pem.Decode(bytes)
	for decoded != nil {

		parsed, err := x509.ParseCertificate(decoded.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "error parsing certificates")
		}

		result = append(result, parsed)

		decoded, tail = pem.Decode(tail)
	}

	return result, nil
}

// decodeKeys decodes PEM encoded RSA keys. Note that unparsable values outside a PEM block are ignored while unparsable
// values inside a PEM block will result in an error.
func decodeKeys(bytes []byte) ([]*rsa.PrivateKey, error) {

	var result []*rsa.PrivateKey

	decoded, tail := pem.Decode(bytes)
	for decoded != nil {

		parsed, err := x509.ParsePKCS1PrivateKey(decoded.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "error parsing keys")
		}

		result = append(result, parsed)

		decoded, tail = pem.Decode(tail)
	}

	return result, nil
}

// loadResource loads a resource URL into a byte array.
func loadResource(resource string) ([]byte, error) {

	parsed, err := url.Parse(resource)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing url from [%s]", resource)
	}

	bytes, err := urls.ReadFile(parsed)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading resource from [%s]", resource)
	}

	return bytes, nil
}
