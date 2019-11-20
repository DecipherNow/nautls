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

package tests

import (
	"crypto/tls"
	"io/ioutil"
	"path/filepath"
	"testing"
)

// MustAbsolutePath returns the absolute path to a file or fails the provided test.
func MustAbsolutePath(path string, test *testing.T) string {
	p, err := filepath.Abs(path)
	if err != nil {
		test.Errorf("failed to resolve absolute path [%s]", path)
	}
	return p
}

// MustRead reads the content of a file or fails the provided test.
func MustRead(path string, test *testing.T) []byte {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		test.Errorf("failed to read file [%s]", path)
	}
	return bytes
}

// MustLoadX509KeyPair loads a tls.Certificate from PEM encoded key pair files or fails the test.
func MustLoadX509KeyPair(certificate string, key string, test *testing.T) tls.Certificate {
	c, err := tls.LoadX509KeyPair(certificate, key)
	if err != nil {
		test.Errorf("error reading key pair [%s]", err)
	}
	return c
}
