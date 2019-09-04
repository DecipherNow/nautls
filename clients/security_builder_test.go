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
	"testing"

	"github.com/deciphernow/nautls/internal/tests"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSecurityBuilder(t *testing.T) {

	Convey("When SecurityBuilder", t, func() {

		builder := NewSecurityBuilder()

		Convey(".Build is invoked", func() {

			config, err := builder.Build()

			Convey("it returns a nil error", func() {
				So(err, ShouldBeNil)
			})

			Convey("it returns the configuration", func() {
				So(config, ShouldNotBeZeroValue)
			})
		})

		Convey(".WithAuthority is invoked", func() {

			authorities := tests.MustGenerateStrings(t)

			builder.WithAuthorities(authorities)

			Convey("it sets the authorities", func() {
				So(builder.config.Authorities, ShouldResemble, authorities)
			})
		})

		Convey(".WithCertificate is invoked", func() {

			certificate := tests.MustGenerateString(t)

			builder.WithCertificate(certificate)

			Convey("it sets the certificate", func() {
				So(builder.config.Certificate, ShouldEqual, certificate)
			})
		})

		Convey(".WithKey is invoked", func() {

			key := tests.MustGenerateString(t)

			builder.WithKey(key)

			Convey("it sets the key", func() {
				So(builder.config.Key, ShouldEqual, key)
			})
		})

		Convey(".WithServer is invoked", func() {

			server := tests.MustGenerateString(t)

			builder.WithServer(server)

			Convey("it sets the server", func() {
				So(builder.config.Server, ShouldEqual, server)
			})
		})
	})
}
