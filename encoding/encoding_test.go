package encoding

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/deciphernow/nautls/identities"
	. "github.com/smartystreets/goconvey/convey"
)

func testCert(t *testing.T) *identities.Identity {
	template := identities.Template{
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

	ident, err := identities.Self(template)
	if err != nil {
		t.Fatalf("error creating identity: %s", err)
	}

	return ident
}

func testKey(t *testing.T) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("error generating private key: %s", err)
	}
	return key
}

func TestPEMEncodeCertificate(t *testing.T) {
	Convey("When PEMEncodeCertificate is called", t, func() {
		Convey("with a nil certificate", func() {
			cert := PEMEncodeCertificate(nil)

			Convey("it should return an empty slice", func() {
				So(cert, ShouldBeEmpty)
			})
		})

		Convey("with a valid certificate", func() {
			ident := testCert(t)
			certPEM := PEMEncodeCertificate(ident.Certificate)
			decoded, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(decoded.Bytes)

			Convey("it should return a nil error", func() {
				So(err, ShouldBeNil)
			})

			Convey("ParseCertificate should return a valid PEM encoded certificate", func() {
				So(*cert, ShouldResemble, *ident.Certificate)
			})
		})
	})
}

func TestPEMEncodeCertificates(t *testing.T) {
	Convey("When PEMEncodeCertificates is called", t, func() {
		Convey("with an empty slice", func() {
			certs := PEMEncodeCertificates([]*x509.Certificate{})

			Convey("it should return an empty slice", func() {
				So(certs, ShouldBeEmpty)
			})
		})

		Convey("with one cert", func() {
			cert := testCert(t)
			certs := PEMEncodeCertificates([]*x509.Certificate{cert.Certificate})

			Convey("it should return one cert", func() {
				So(len(certs), ShouldEqual, 1)
			})
		})

		Convey("with multiple certs", func() {
			cert := testCert(t)
			certs := PEMEncodeCertificates([]*x509.Certificate{cert.Certificate, cert.Certificate})

			Convey("it should return the right number of certs", func() {
				So(len(certs), ShouldEqual, 2)
			})
		})
	})
}

func TestPEMEncodeKey(t *testing.T) {
	Convey("When PEMEncodeKey is called", t, func() {
		Convey("With a nil key", func() {
			key := PEMEncodeKey(nil)

			Convey("it should return an empty slice", func() {
				So(key, ShouldBeEmpty)
			})
		})

		Convey("with a valid key", func() {
			key := testKey(t)
			keyPEM := PEMEncodeKey(key)
			decoded, _ := pem.Decode(keyPEM)
			decodedKey, err := x509.ParsePKCS1PrivateKey(decoded.Bytes)

			Convey("ParsePKCS1PrivateKey should return a valid key", func() {
				So(err, ShouldBeNil)
			})

			Convey("it should return a valid rsa private key", func() {
				So(decodedKey, ShouldResemble, key)
			})
		})
	})
}

func TestPEMEncodeKeys(t *testing.T) {
	Convey("When PEMEncodeKeys is called", t, func() {
		Convey("with an empty slice", func() {
			keys := PEMEncodeKeys([]*rsa.PrivateKey{})

			Convey("it should return an empty slice", func() {
				So(keys, ShouldBeEmpty)
			})
		})

		Convey("with valid keys", func() {
			keys := PEMEncodeKeys([]*rsa.PrivateKey{testKey(t), testKey(t)})

			Convey("it should return the right number of keys", func() {
				So(len(keys), ShouldEqual, 2)
			})
		})
	})
}
