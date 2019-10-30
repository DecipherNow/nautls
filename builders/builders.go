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

package builders

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"

	"github.com/deciphernow/nautls/internal/urls"
	"github.com/pkg/errors"
)

// BuildCertificatePool provides a utility function for creating a certificate pool from an array of URLs. Note that if
// the array of URLs is empty the system certificates will be used.
func BuildCertificatePool(certificateURLs []string) (*x509.CertPool, error) {

	if len(certificateURLs) == 0 {
		return x509.SystemCertPool()
	}

	pool := x509.NewCertPool()
	for _, certificate := range certificateURLs {

		bytes, err := readResource(certificate)
		if err != nil {
			return nil, errors.Wrapf(err, "error reading certificate [%s]", certificate)
		}

		if !pool.AppendCertsFromPEM(bytes) {
			return nil, errors.Wrapf(err, "error appending certificate from [%s]", certificate)
		}
	}

	return pool, nil
}

// BuildCertificates provides a utility function for loading a certificate from certificate and key URLs.
func BuildCertificates(certificateURL string, keyURL string) ([]tls.Certificate, error) {

	certificates := []tls.Certificate{}

	if (certificateURL == "") && (keyURL == "") {
		return certificates, nil
	}

	certificate, err := readKeyPair(certificateURL, keyURL)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading key pair from [%s] and [%s]", certificateURL, keyURL)
	}

	return append(certificates, certificate), nil
}

// readKeyPair reads an X.509 key pair from a certificate and key URL.
func readKeyPair(certificateURL string, keyURL string) (tls.Certificate, error) {

	certificateBytes, err := readResource(certificateURL)
	if err != nil {
		return tls.Certificate{}, errors.Wrapf(err, "error reading certificate [%s]", certificateURL)
	}

	keyBytes, err := readResource(keyURL)
	if err != nil {
		return tls.Certificate{}, errors.Wrapf(err, "error reading key [%s]", keyURL)
	}

	return tls.X509KeyPair(certificateBytes, keyBytes)
}

// readResource reads a resource URL into a byte array.
func readResource(resource string) ([]byte, error) {

	resourceURL, err := url.Parse(resource)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing url from [%s]", resource)
	}

	resourceBytes, err := urls.ReadFile(resourceURL)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading resource from [%s]", resourceURL)
	}

	return resourceBytes, nil
}
