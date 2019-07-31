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
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

var (
	// Random provides a random source for tests.
	Random = rand.New(rand.NewSource(time.Now().Unix()))
)

// MustGenerate generates and returns a random value of a type or fails a test.
func MustGenerate(tipe reflect.Type, test *testing.T) reflect.Value {

	value, ok := quick.Value(tipe, Random)
	if !ok {
		test.Errorf("unable to generate random value of type [%s]", tipe)
	}

	return value
}

// MustGenerateBytes generates a random slice of bytes or fails a test.
func MustGenerateBytes(test *testing.T) []byte {
	return MustGenerate(reflect.TypeOf([]byte{}), test).Interface().([]byte)
}

// MustGenerateHex generates a random hexidecimal string or fails a test.
func MustGenerateHex(test *testing.T) string {
	return hex.EncodeToString(MustGenerateBytes(test))
}

// MustGenerateHexes generates a random slice of hexidecimal strings or fails a test.
func MustGenerateHexes(test *testing.T) []string {
	byteses := MustGenerate(reflect.TypeOf([][]byte{}), test).Interface().([][]byte)
	hexes := make([]string, len(byteses))
	for index, bytes := range byteses {
		hexes[index] = hex.EncodeToString(bytes)
	}
	return hexes
}

// MustGenerateInt generates a random integer or fails a test.
func MustGenerateInt(test *testing.T) int {
	return MustGenerate(reflect.TypeOf(1), test).Interface().(int)
}

// MustGenerateString generates a random string or fails a test.
func MustGenerateString(test *testing.T) string {
	return MustGenerate(reflect.TypeOf(""), test).Interface().(string)
}

// MustGenerateStrings generates a random slice of strings or fails a test.
func MustGenerateStrings(test *testing.T) []string {
	return MustGenerate(reflect.TypeOf([]string{}), test).Interface().([]string)
}

// MustGenerateUint generates a random integer or fails a test.
func MustGenerateUint(test *testing.T) uint {
	return MustGenerate(reflect.TypeOf(uint(1)), test).Interface().(uint)
}

// MustGenerateURL generates a random *url.URL or fails a test.
func MustGenerateURL(test *testing.T) *url.URL {

	scheme := []string{"base64", "http", "https", "file", "ftp", "sftp", "ssh"}[Random.Intn(7)]
	host := MustGenerateHex(test)
	port := MustGenerateUint(test) % 65535
	path := strings.Join(MustGenerateHexes(test), "/")

	value, err := url.Parse(fmt.Sprintf("%s://%s:%d/%s", scheme, host, port, path))
	if err != nil {
		test.Errorf("unable to generate random value of type [*url.URL] with error [%s]", err.Error())
	}

	return value
}
