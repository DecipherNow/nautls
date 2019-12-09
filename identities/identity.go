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
	"crypto/x509/pkix"
	"hash"
	"time"

	"github.com/pkg/errors"
)

// Identity represents an X.509 identity.
type Identity struct {
	authorities []*x509.Certificate
	certificate *x509.Certificate
	key         *rsa.PrivateKey
}

// NewIdentity returns a new identity.
func NewIdentity(authorities []*x509.Certificate, certificate *x509.Certificate, key *rsa.PrivateKey) *Identity {
	return &Identity{
		authorities: authorities,
		certificate: certificate,
		key:         key,
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

// Expiration returns the expiration date of this identity.
func (i *Identity) Expiration() time.Time {
	return i.certificate.NotAfter
}

// Fingerprint returns the result of invoking hash.Sum with the raw content of this identities certificate.
func (i *Identity) Fingerprint(hasher hash.Hash) []byte {
	return hasher.Sum(i.certificate.Raw)
}

// Issue returns a new identity signed by this identity based upon a template.
func (i *Identity) Issue(template Template) (*Identity, error) {

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, errors.Wrapf(err, "error generating private key for [%s]", template.Subject.CommonName)
	}

	certificate, err := sign(template.certificate(), template.certificate(), &key.PublicKey, key)
	if err != nil {
		return nil, errors.Wrapf(err, "error signing certificate for [%s]", template.Subject.CommonName)
	}

	return NewIdentity(append(i.authorities, i.certificate), certificate, key), nil
}

// Subject returns the subject of this identity.
func (i *Identity) Subject() pkix.Name {
	return i.certificate.Subject
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
