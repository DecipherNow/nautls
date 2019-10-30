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
	"os"
	"path/filepath"
	"regexp"

	"github.com/hashicorp/go-getter"
	"github.com/pkg/errors"
)

var (
	regex = regexp.MustCompile(`^\/*`)
)

// Base64 implements a getter.Getter that converts an inline Base64 encoded string into a file.
type Base64 struct{}

// Get downloads the given URL into the given directory. This always returns an error for this getter.
func (b *Base64) Get(_ string, _ *url.URL) error {
	return errors.New("directory fetching is not supported for scheme [base64]")
}

// GetFile downloads the given URL into the given path. The URL must reference a single file.
func (b *Base64) GetFile(destination string, source *url.URL) error {

	path, err := url.PathUnescape(source.Path)
	if err != nil {
		return errors.Wrapf(err, "error unescaping value [%s]", source.Path)
	}

	data, err := base64.StdEncoding.DecodeString(regex.ReplaceAllString(path, ""))
	if err != nil {
		return errors.Wrapf(err, "error decoding value [%s]", path)
	}

	err = writeFile(destination, data)
	if err != nil {
		return errors.Wrapf(err, "error writing file [%s]", path)
	}

	return nil
}

// ClientMode returns the mode based on the given URL. This is always returns ClientModeFile for this getter.
func (b *Base64) ClientMode(_ *url.URL) (getter.ClientMode, error) {
	return getter.ClientModeFile, nil
}

// SetClient sets the client for this getter.  This is a noop for this getter.
func (b *Base64) SetClient(_ *getter.Client) {}

// writeFile writes data to a provided path ensuring that the directories exist if not present.
func writeFile(path string, data []byte) error {

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return errors.Wrapf(err, "error creating parent directories [%s]", path)
	}

	if err := ioutil.WriteFile(path, data, os.FileMode(0666)); err != nil {
		return errors.Wrapf(err, "error writing data to file [%s]", path)
	}

	return nil
}
