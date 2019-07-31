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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// Callback defines the callback function signature.
type Callback func(path string) (interface{}, error)

// Directory creates a temporary directory and returns the path or an error.
func Directory() (string, error) {

	path, err := ioutil.TempDir("", "temporary-")
	if err != nil {
		return "", errors.Wrap(err, "error creating temporary directory")
	}

	return path, nil
}

// WithDirectory creates a temporary directory and invokes the callback and returns the result.
func WithDirectory(callback Callback) (interface{}, error) {

	path, err := Directory()
	if err != nil {
		return nil, err
	}

	defer os.RemoveAll(path)

	return callback(path)
}

// WithFile creates a temporary file with content and permissions, invokes the callback and returns the result.
func WithFile(content []byte, permission os.FileMode, callback Callback) (interface{}, error) {

	return WithDirectory(func(directory string) (interface{}, error) {
		file := filepath.Join(directory, "file")
		ioutil.WriteFile(file, content, permission)
		return callback(file)
	})
}
