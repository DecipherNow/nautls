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
	"fmt"
	"testing"

	"github.com/deciphernow/nautls/internal/tests"

	. "github.com/smartystreets/goconvey/convey"
)

func TestIdentityBuilder(t *testing.T) {

	Convey("When IdentityBuilder", t, func() {

		builder := NewIdentityBuilder()
		builder.WithAuthorities(fmt.Sprintf("file://%s", tests.MustAbsolutePath("testdata/multiple.crt", t)))
		builder.WithCertificate(fmt.Sprintf("file://%s", tests.MustAbsolutePath("testdata/single.crt", t)))
		builder.WithKey(fmt.Sprintf("file://%s", tests.MustAbsolutePath("testdata/single.key", t)))

		Convey(".Build is invoked", func() {

			Convey("with empty authorities", func() {

				builder.WithAuthorities(fmt.Sprintf("file://%s", tests.MustAbsolutePath("testdata/empty.crt", t)))
				identity, err := builder.Build()

				Convey("it should return a non-nil identity", func() {
					So(identity, ShouldNotBeNil)
				})

				Convey("it should return a nil error", func() {
					So(err, ShouldBeNil)
				})
			})

			Convey("with invalid authorities", func() {

				builder.WithAuthorities(fmt.Sprintf("file://%s", tests.MustAbsolutePath("testdata/invalid.crt", t)))
				identity, err := builder.Build()

				Convey("it should return a nil identity", func() {
					So(identity, ShouldBeNil)
				})

				Convey("it should return a non-nil error", func() {
					So(err, ShouldNotBeNil)
				})
			})

			Convey("with an empty certificate", func() {

				builder.WithCertificate(fmt.Sprintf("file://%s", tests.MustAbsolutePath("testdata/empty.crt", t)))
				identity, err := builder.Build()

				Convey("it should return a nil identity", func() {
					So(identity, ShouldBeNil)
				})

				Convey("it should return a non-nil error", func() {
					So(err, ShouldNotBeNil)
				})
			})

			Convey("with an invalid certificate", func() {

				builder.WithCertificate(fmt.Sprintf("file://%s", tests.MustAbsolutePath("testdata/invalid.crt", t)))
				identity, err := builder.Build()

				Convey("it should return a nil identity", func() {
					So(identity, ShouldBeNil)
				})

				Convey("it should return a non-nil error", func() {
					So(err, ShouldNotBeNil)
				})
			})

			Convey("with multiple certificates", func() {

				builder.WithCertificate(fmt.Sprintf("file://%s", tests.MustAbsolutePath("testdata/multiple.crt", t)))
				identity, err := builder.Build()

				Convey("it should return a nil identity", func() {
					So(identity, ShouldBeNil)
				})

				Convey("it should return a non-nil error", func() {
					So(err, ShouldNotBeNil)
				})
			})

			Convey("with an empty key", func() {

				builder.WithKey(fmt.Sprintf("file://%s", tests.MustAbsolutePath("testdata/empty.key", t)))
				identity, err := builder.Build()

				Convey("it should return a nil identity", func() {
					So(identity, ShouldBeNil)
				})

				Convey("it should return a non-nil error", func() {
					So(err, ShouldNotBeNil)
				})
			})

			Convey("with an invalid key", func() {

				builder.WithKey(fmt.Sprintf("file://%s", tests.MustAbsolutePath("testdata/invalid.key", t)))
				identity, err := builder.Build()

				Convey("it should return a nil identity", func() {
					So(identity, ShouldBeNil)
				})

				Convey("it should return a non-nil error", func() {
					So(err, ShouldNotBeNil)
				})
			})

			Convey("with multiple keys", func() {

				builder.WithKey(fmt.Sprintf("file://%s", tests.MustAbsolutePath("testdata/multiple.key", t)))
				identity, err := builder.Build()

				Convey("it should return a nil identity", func() {
					So(identity, ShouldBeNil)
				})

				Convey("it should return a non-nil error", func() {
					So(err, ShouldNotBeNil)
				})
			})
		})
	})
}
