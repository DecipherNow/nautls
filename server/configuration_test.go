package server

import (
	"crypto/tls"
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestAuthentication(t *testing.T) {

	authentications := map[Authentication]string{
		Authentication(tls.NoClientCert):               "NoClientCert",
		Authentication(tls.RequestClientCert):          "RequestClientCert",
		Authentication(tls.RequireAnyClientCert):       "RequireAnyClientCert",
		Authentication(tls.VerifyClientCertIfGiven):    "VerifyClientCertIfGiven",
		Authentication(tls.RequireAndVerifyClientCert): "RequireAndVerifyClientCert",
	}

	Convey("When Authentication", t, func() {

		Convey(".ToString is invoked", func() {

			for authentication, expected := range authentications {

				Convey(fmt.Sprintf("on %d", authentication), func() {

					actual, err := authentication.ToString()

					Convey(fmt.Sprintf("it returns %s", expected), func() {
						So(actual, ShouldEqual, expected)
					})

					Convey("it returns a nil error", func() {
						So(err, ShouldBeNil)
					})
				})
			}
		})

		Convey(".FromString is invoked", func() {

			for expected, value := range authentications {

				Convey(fmt.Sprintf("with %s", value), func() {

					var actual Authentication

					err := actual.FromString(value)

					Convey(fmt.Sprintf("it sets the authentication to %d", expected), func() {
						So(actual, ShouldEqual, expected)
					})

					Convey("it returns a nil error", func() {
						So(err, ShouldBeNil)
					})
				})
			}
		})
	})
}
