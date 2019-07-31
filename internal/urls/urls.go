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

package urls

import (
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"

	"github.com/deciphernow/nautls/internal/temporary"
	"github.com/deciphernow/nautls/internal/urls/getters"
	"github.com/hashicorp/go-getter"
	"github.com/pkg/errors"
)

func init() {
	getter.Getters["base64"] = &getters.Base64{}
}

// File gets the provided resource to a temporary file on the local machine and returns the path.
func File(resource *url.URL) (string, error) {

	directory, err := temporary.Directory()
	if err != nil {
		return "", errors.Wrap(err, "error creating directory")
	}

	destination := filepath.Join(directory, "resource")

	err = getter.GetFile(destination, resource.String())
	if err != nil {
		return "", errors.Wrapf(err, "error fetching resource from [%s] to [%s]", resource.String(), destination)
	}

	return destination, nil
}

// WithFile gets the provided resource to a temporary file on the local machine, invokes the callback with the path and
// returns the result.  Note that the temporary file is deleted when the callback returns.
func WithFile(resource *url.URL, callback func(path string) (interface{}, error)) (interface{}, error) {

	destination, err := File(resource)
	if err != nil {
		return nil, err
	}

	defer os.RemoveAll(destination)

	return callback(destination)
}

// ReadFile returns the content of the provided resource as an array of bytes or returns an error.
func ReadFile(resource *url.URL) ([]byte, error) {

	bytes, err := WithFile(resource, func(path string) (interface{}, error) {
		return ioutil.ReadFile(path)
	})

	if err != nil {
		return nil, errors.Wrapf(err, "error reading resource [%s]", resource)
	}

	return bytes.([]byte), nil
}
