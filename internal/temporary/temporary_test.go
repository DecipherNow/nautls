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

package temporary

import (
	"os"
	"testing"

	"github.com/deciphernow/nautls/internal/tests"
	"github.com/pkg/errors"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDirectory(test *testing.T) {

	Convey("When .Directory is invoked", test, func() {

		path, err := Directory()
		exists := isDirectory(path)
		defer os.RemoveAll(path)

		Convey("it returns a nil error", func() {
			So(err, ShouldBeNil)
		})

		Convey("it returns a valid directory", func() {
			So(exists, ShouldBeTrue)
		})
	})
}

func TestWithDirectory(test *testing.T) {

	Convey("When .WithDirectory is invoked", test, func() {

		expectedValue := &struct{}{}
		expectedError := errors.New(tests.MustGenerateString(test))
		directory := tests.MustGenerateString(test)
		existed := false

		actualValue, actualError := WithDirectory(func(path string) (interface{}, error) {
			directory = path
			existed = isDirectory(path)
			return expectedValue, expectedError
		})

		exists := isDirectory(directory)

		Convey("it returns the expected error", func() {
			So(actualError, ShouldEqual, expectedError)
		})

		Convey("it returns the expected value", func() {
			So(actualValue, ShouldEqual, expectedValue)
		})

		Convey("it invokes the callback with a directory", func() {
			So(existed, ShouldBeTrue)
		})

		Convey("it deletes the directory after the callback returns", func() {
			So(exists, ShouldBeFalse)
		})
	})
}

// exists returns a value indicating whether the provided path is a directory.
func isDirectory(path string) bool {

	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	return info.IsDir()
}
