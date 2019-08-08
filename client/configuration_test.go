package client

import (
	"testing"

	"github.com/deciphernow/nautls/internal/tests"

	. "github.com/smartystreets/goconvey/convey"
)

func TestConfiguration(t *testing.T) {

	Convey("When Configuration", t, func() {

		configuration := &Configuration{}

		Convey(".Build is invoked", func() {

			tls, err := configuration.Build()

			Convey("it returns a nil error", func() {
				So(err, ShouldBeNil)
			})

			Convey("it returns the configuration", func() {
				So(tls, ShouldNotBeZeroValue)
			})
		})

		Convey(".WithAuthority is invoked", func() {

			authority := tests.MustGenerateString(t)
			authorities := []string{authority}

			configuration.WithAuthority(authority)

			Convey("it sets the authority", func() {
				So(configuration.Authorities, ShouldResemble, authorities)
			})
		})

		Convey(".WithCertificate is invoked", func() {

			certificate := tests.MustGenerateString(t)

			configuration.WithCertificate(certificate)

			Convey("it sets the certificate", func() {
				So(configuration.Certificate, ShouldEqual, certificate)
			})
		})

		Convey(".WithKey is invoked", func() {

			key := tests.MustGenerateString(t)

			configuration.WithKey(key)

			Convey("it sets the key", func() {
				So(configuration.Key, ShouldEqual, key)
			})
		})

		Convey(".WithServer is invoked", func() {

			server := tests.MustGenerateString(t)

			configuration.WithServer(server)

			Convey("it sets the server", func() {
				So(configuration.Server, ShouldEqual, server)
			})
		})
	})
}
