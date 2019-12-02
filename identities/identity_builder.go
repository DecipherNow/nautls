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

// IdentityBuilder provides an builder for Identity instances.
type IdentityBuilder struct {
	config IdentityConfig
}

// NewIdentityBuilder returns a new instance of the IdentityBuilder structure.
func NewIdentityBuilder() *IdentityBuilder {
	return &IdentityBuilder{}
}

// Build creates a Identity from the IdentityBuilder.
func (b *IdentityBuilder) Build() (*Identity, error) {
	return b.config.Build()
}

// WithAuthorities sets the certificate authorities that issued the identity. The value must be a URL that points to the
// location of PEM encoded certificates.
//
// Note that in addition to those schemes supported by [getter](https://godoc.org/github.com/hashicorp/go-getter) a
// "base64" scheme is supported for providing the PEM encoded certifiate in the path of the URL directly. This is most
// applicable when the certificate data must be provided via an environement variable.
func (b *IdentityBuilder) WithAuthorities(authorities string) *IdentityBuilder {
	b.config.Authorities = authorities
	return b
}

// WithCertificate sets the certificate for the identity. The value must be a URL that points to the location of a PEM
// encoded X.509 certificate.
//
// Note that in addition to those schemes supported by [getter](https://godoc.org/github.com/hashicorp/go-getter) a
// "base64" scheme is supported for providing the PEM encoded certifiate in the path of the URL directly. This is most
// applicable when the certificate data must be provided via an environement variable.
func (b *IdentityBuilder) WithCertificate(certificate string) *IdentityBuilder {
	b.config.Certificate = certificate
	return b
}

// WithKey sets the key for the identity. The value must be a URL that points to the location of a PEM encoded RSA key.
//
// Note that in addition to those schemes supported by [getter](https://godoc.org/github.com/hashicorp/go-getter) a
// "base64" scheme is supported for providing the PEM encoded certifiate in the path of the URL directly. This is most
// applicable when the certificate data must be provided via an environement variable.
func (b *IdentityBuilder) WithKey(key string) *IdentityBuilder {
	b.config.Key = key
	return b
}
