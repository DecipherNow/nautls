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
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestIdentity(t *testing.T) {

	Convey("When IdentityConfig", t, func() {

		Convey(".NewIdentity is invoked", func() {

			authorities := []*x509.Certificate{&x509.Certificate{}}
			certificate := &x509.Certificate{}
			key := &rsa.PrivateKey{}
			identity := NewIdentity(authorities, certificate, key)

			Convey("it returns an instance", func() {

				Convey("with the correct authorities", func() {
					So(identity.Authorities, ShouldResemble, authorities)
				})

				Convey("with the correct certificate", func() {
					So(identity.Certificate, ShouldEqual, certificate)
				})

				Convey("with the correct key", func() {
					So(identity.Key, ShouldEqual, key)
				})
			})
		})

		Convey(".Self is invoked", func() {

			Convey("with an unauthorative template", func() {

				template := Template{}
				identity, err := Self(template)

				Convey("it returns a nil identity", func() {
					So(identity, ShouldBeNil)
				})

				Convey("it returns a non-nil error", func() {
					So(err, ShouldNotBeNil)
				})
			})

			Convey("with an valid template", func() {

				template := Template{
					BasicConstraintsValid: true,
					ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
					IsCA:                  false,
					KeyUsage:              x509.KeyUsageDigitalSignature,
					NotAfter:              time.Now().AddDate(10, 0, 0),
					NotBefore:             time.Now(),
					SerialNumber:          big.NewInt(time.Now().Unix()),
					Subject: pkix.Name{
						CommonName:         "NauTLS (Leaf)",
						Country:            []string{"US"},
						Locality:           []string{"Alexandria"},
						Organization:       []string{"Decipher Technology Studios"},
						OrganizationalUnit: []string{"Engineering"},
						Province:           []string{"Virginia"},
						PostalCode:         []string{"22314"},
						StreetAddress:      []string{"110 S. Union St, Floor 2"},
					},
				}

				identity, err := Self(template)

				Convey("it returns a non-nil identity", func() {
					So(identity, ShouldNotBeNil)
				})

				Convey("it returns a nil error", func() {
					So(err, ShouldBeNil)
				})
			})
		})

		Convey(".Issue is invoked", func() {

			root, _ := Self(Template{
				BasicConstraintsValid: true,
				ExtKeyUsage:           []x509.ExtKeyUsage{},
				IsCA:                  true,
				KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
				NotAfter:              time.Now().AddDate(10, 0, 0),
				NotBefore:             time.Now(),
				SerialNumber:          big.NewInt(time.Now().Unix()),
				Subject: pkix.Name{
					CommonName:         "NauTLS (Root)",
					Country:            []string{"US"},
					Locality:           []string{"Alexandria"},
					Organization:       []string{"Decipher Technology Studios"},
					OrganizationalUnit: []string{"Engineering"},
					Province:           []string{"Virginia"},
					PostalCode:         []string{"22314"},
					StreetAddress:      []string{"110 S. Union St, Floor 2"},
				},
			})

			intermediate, _ := root.Issue(Template{
				BasicConstraintsValid: true,
				ExtKeyUsage:           []x509.ExtKeyUsage{},
				IsCA:                  true,
				KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
				NotAfter:              time.Now().AddDate(10, 0, 0),
				NotBefore:             time.Now(),
				SerialNumber:          big.NewInt(time.Now().Unix()),
				Subject: pkix.Name{
					CommonName:         "NauTLS (Intermediate)",
					Country:            []string{"US"},
					Locality:           []string{"Alexandria"},
					Organization:       []string{"Decipher Technology Studios"},
					OrganizationalUnit: []string{"Engineering"},
					Province:           []string{"Virginia"},
					PostalCode:         []string{"22314"},
					StreetAddress:      []string{"110 S. Union St, Floor 2"},
				},
			})

			identity, err := intermediate.Issue(Template{
				BasicConstraintsValid: true,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
				IsCA:                  false,
				KeyUsage:              x509.KeyUsageDigitalSignature,
				NotAfter:              time.Now().AddDate(10, 0, 0),
				NotBefore:             time.Now(),
				SerialNumber:          big.NewInt(time.Now().Unix()),
				Subject: pkix.Name{
					CommonName:         "nautls.com",
					Country:            []string{"US"},
					Locality:           []string{"Alexandria"},
					Organization:       []string{"Decipher Technology Studios"},
					OrganizationalUnit: []string{"Engineering"},
					Province:           []string{"Virginia"},
					PostalCode:         []string{"22314"},
					StreetAddress:      []string{"110 S. Union St, Floor 2"},
				},
			})

			roots := x509.NewCertPool()
			roots.AddCert(root.Certificate)

			intermediates := x509.NewCertPool()
			intermediates.AddCert(intermediate.Certificate)

			options := x509.VerifyOptions{
				DNSName:       "nautls.com",
				Intermediates: intermediates,
				Roots:         roots,
			}

			Convey("it returns a verifiable identity", func() {
				_, err := identity.Certificate.Verify(options)
				So(err, ShouldBeNil)
			})

			Convey("it returns a nil error", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}
