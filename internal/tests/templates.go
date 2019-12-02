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
	"bytes"
	"path/filepath"
	"testing"
	"text/template"
)

// MustTemplate returns the provided template rendered with the values or fails the test.
func MustTemplate(path string, values map[string]string, test *testing.T) []byte {

	tpl, err := template.New(filepath.Base(path)).Parse(string(MustRead(path, test)))
	if err != nil {
		test.Errorf("unable to parse template [%s]", path)
	}

	var buffer bytes.Buffer

	err = tpl.Execute(&buffer, values)
	if err != nil {
		test.Errorf("unable to execute template [%s] [%s]", path, err.Error())
	}

	return buffer.Bytes()
}
