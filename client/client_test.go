package client

import (
	"reflect"
	"testing"

	"github.com/deciphernow/nautls/internal/tests"

	. "github.com/smartystreets/goconvey/convey"
)

func TestClient(t *testing.T) {

	Convey("When Client", t, func() {

		client := &Client{}

		Convey(".WithHost is invoked", func() {

			host := tests.MustGenerateString(t)

			client.WithHost(host)

			Convey("it sets the host", func() {
				So(client.Host, ShouldEqual, host)
			})
		})

		Convey(".WithPort is invoked", func() {

			port := tests.MustGenerateInt(t)

			client.WithPort(port)

			Convey("it sets the port", func() {
				So(client.Port, ShouldEqual, port)
			})
		})

		Convey(".WithTLS is invoked", func() {

			tls := tests.MustGenerate(reflect.TypeOf(Configuration{}), t).Interface().(Configuration)

			client.WithTLS(tls)

			Convey("it sets the tls", func() {
				So(client.TLS, ShouldResemble, tls)
			})
		})

		Convey(".Build is invoked", func() {

			http, err := client.Build()

			Convey("it returns a nil error", func() {
				So(err, ShouldBeNil)
			})

			Convey("it returns the client", func() {
				So(http, ShouldNotBeZeroValue)
			})
		})
	})
}
