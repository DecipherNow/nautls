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

package clients

import (
	"reflect"
	"testing"

	"github.com/deciphernow/nautls/internal/tests"

	. "github.com/smartystreets/goconvey/convey"
)

func TestClientBuilder(t *testing.T) {

	Convey("When ClientBuilder", t, func() {

		builder := NewClientBuilder()

		Convey(".WithHost is invoked", func() {

			host := tests.MustGenerateString(t)

			builder.WithHost(host)

			Convey("it sets the host", func() {
				So(builder.config.Host, ShouldEqual, host)
			})
		})

		Convey(".WithPort is invoked", func() {

			port := tests.MustGenerateInt(t)

			builder.WithPort(port)

			Convey("it sets the port", func() {
				So(builder.config.Port, ShouldEqual, port)
			})
		})

		Convey(".WithTLS is invoked", func() {

			security := tests.MustGenerate(reflect.TypeOf(SecurityConfig{}), t).Interface().(SecurityConfig)

			builder.WithSecurity(security)

			Convey("it sets the tls", func() {
				So(builder.config.Security, ShouldResemble, security)
			})
		})

		Convey(".Build is invoked", func() {

			client, err := builder.Build()

			Convey("it returns a nil error", func() {
				So(err, ShouldBeNil)
			})

			Convey("it returns the client", func() {
				So(client, ShouldNotBeZeroValue)
			})
		})
	})
}
