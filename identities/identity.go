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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/pkg/errors"
)

// Identity represents an X.509 identity.
type Identity struct {
	Authorities []*x509.Certificate
	Certificate *x509.Certificate
	Key         *rsa.PrivateKey
}

// NewIdentity returns a new identity.
func NewIdentity(authorities []*x509.Certificate, certificate *x509.Certificate, key *rsa.PrivateKey) *Identity {
	return &Identity{
		Authorities: authorities,
		Certificate: certificate,
		Key:         key,
	}
}

// Self generates a self signed identity (e.g., a root).
func Self(template Template) (*Identity, error) {

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, errors.Wrapf(err, "error generating private key for [%s]", template.Subject.CommonName)
	}

	certificate, err := sign(template.certificate(), template.certificate(), &key.PublicKey, key)
	if err != nil {
		return nil, errors.Wrapf(err, "error signing certificate for [%s]", template.Subject.CommonName)
	}

	return NewIdentity([]*x509.Certificate{}, certificate, key), nil
}

// Issue returns a new identity signed by this identity based upon a template.
func (i *Identity) Issue(template Template) (*Identity, error) {

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, errors.Wrapf(err, "error generating private key for [%s]", template.Subject.CommonName)
	}

	certificate, err := sign(template.certificate(), i.Certificate, &key.PublicKey, i.Key)
	if err != nil {
		return nil, errors.Wrapf(err, "error signing certificate for [%s]", template.Subject.CommonName)
	}

	return NewIdentity(append([]*x509.Certificate{i.Certificate}, i.Authorities...), certificate, key), nil
}

// sign returns a signed certificate for the provided template.
func sign(template, parent *x509.Certificate, public *rsa.PublicKey, private *rsa.PrivateKey) (*x509.Certificate, error) {

	bytes, err := x509.CreateCertificate(rand.Reader, template, parent, public, private)
	if err != nil {
		return nil, errors.Wrapf(err, "error signing certificate for [%s]", template.Subject.CommonName)
	}

	certificate, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing certificate for [%s]", template.Subject.CommonName)
	}

	return certificate, nil
}
