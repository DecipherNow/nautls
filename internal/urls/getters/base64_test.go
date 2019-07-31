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

package getters

import (
	"encoding/base64"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/deciphernow/nautls/internal/temporary"
	"github.com/deciphernow/nautls/internal/tests"
	"github.com/hashicorp/go-getter"

	. "github.com/smartystreets/goconvey/convey"
)

func TestBase64(test *testing.T) {

	Convey("When Base64", test, func() {

		instance := &Base64{}

		Convey(".Get is invoked", func() {

			Convey("with any parameters", func() {

				destination := tests.MustGenerateString(test)
				resource := tests.MustGenerateURL(test)
				err := instance.Get(destination, resource)

				Convey("it should return a non-nil error", func() {
					So(err, ShouldNotBeNil)
				})
			})
		})

		Convey(".GetFile is invoked", func() {

			var err error

			actualContent := tests.MustGenerateBytes(test)
			expectedContent := tests.MustGenerateBytes(test)
			encodedContent := url.PathEscape(base64.StdEncoding.EncodeToString(expectedContent))
			url, _ := url.Parse("base64:///" + encodedContent)

			temporary.WithDirectory(func(path string) (interface{}, error) {
				destination := filepath.Join(path, "resource")
				instance.GetFile(destination, url)
				actualContent, err = ioutil.ReadFile(destination)
				if err != nil {
					test.Error("failed to read file at path", destination)
				}
				return nil, nil
			})

			Convey("it gets the resource", func() {
				So(actualContent, ShouldResemble, expectedContent)
			})
		})

		Convey(".ClientMode", func() {

			Convey("with any parameters", func() {

				resource := tests.MustGenerateURL(test)
				mode, err := instance.ClientMode(resource)

				Convey("it should return a getter.ClientModeFile", func() {
					So(mode, ShouldEqual, getter.ClientModeFile)
				})

				Convey("it should return a nil error", func() {
					So(err, ShouldBeNil)
				})
			})
		})
	})
}
