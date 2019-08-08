package server

import (
	"crypto/tls"
	"math/rand"
	"reflect"
	"testing"

	"github.com/deciphernow/nautls/internal/tests"
)

// ValidAuthentications returns a map of the valid authentication values and their string representation.
func ValidAuthentications() map[Authentication]string {
	return map[Authentication]string{
		Authentication(tls.NoClientCert):               "NoClientCert",
		Authentication(tls.RequestClientCert):          "RequestClientCert",
		Authentication(tls.RequireAnyClientCert):       "RequireAnyClientCert",
		Authentication(tls.VerifyClientCertIfGiven):    "VerifyClientCertIfGiven",
		Authentication(tls.RequireAndVerifyClientCert): "RequireAndVerifyClientCert",
	}
}

// Generate implements the quick.Generator inteface for authentications.
func (a Authentication) Generate(rand *rand.Rand, size int) reflect.Value {
	authentications := reflect.ValueOf(ValidAuthentications()).MapKeys()
	return authentications[rand.Intn(len(authentications))]
}

// MustGenerateAuthentication generates and returns a random authentication or fails the test.
func MustGenerateAuthentication(t *testing.T) Authentication {
	return tests.MustGenerate(reflect.TypeOf(Authentication(0)), t).Interface().(Authentication)
}
