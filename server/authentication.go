package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
)

// Authentication subtypes tls.ClientAuthType to provide serialization support.
type Authentication tls.ClientAuthType

// MarshalJSON returns a JSON representation of the authentication or an error.
func (a Authentication) MarshalJSON() ([]byte, error) {

	value, err := a.ToString()
	if err != nil {
		return nil, errors.Wrap(err, "error marshalling authentication to json")
	}

	return []byte(fmt.Sprintf("\"%s\"", value)), nil
}

// MarshalYAML returns a YAML representation of the authentication or an error.
func (a Authentication) MarshalYAML() (interface{}, error) {
	return a.ToString()
}

// UnmarshalJSON unmarshals an authentication from JSON or returns an error.
func (a *Authentication) UnmarshalJSON(bytes []byte) error {

	var value string

	err := json.Unmarshal(bytes, &value)
	if err != nil {
		return errors.Wrap(err, "error unmarshalling authentication from json")
	}

	return a.FromString(value)
}

// UnmarshalYAML unmarshals an authentication from YAML or returns an error.
func (a *Authentication) UnmarshalYAML(unmarshal func(interface{}) error) error {

	var value string

	err := unmarshal(&value)
	if err != nil {
		return errors.Wrap(err, "error unmarshalling authentication from yaml")
	}

	return a.FromString(value)
}

// FromString sets the value of an authentication to the value represented by a string or errors.
func (a *Authentication) FromString(value string) error {

	var authentication Authentication

	switch strings.ToLower(value) {
	case "noclientcert":
		authentication = Authentication(tls.NoClientCert)
	case "requestclientcert":
		authentication = Authentication(tls.RequestClientCert)
	case "requireanyclientcert":
		authentication = Authentication(tls.RequireAnyClientCert)
	case "verifyclientcertifgiven":
		authentication = Authentication(tls.VerifyClientCertIfGiven)
	case "requireandverifyclientcert":
		authentication = Authentication(tls.RequireAndVerifyClientCert)
	default:
		return errors.New(fmt.Sprintf("error unmarshalling unknown authentication value [%s]", value))
	}

	*a = authentication

	return nil
}

// ToString returns the string representation of the authentication or an error.
func (a Authentication) ToString() (string, error) {

	switch tls.ClientAuthType(a) {
	case tls.NoClientCert:
		return "NoClientCert", nil
	case tls.RequestClientCert:
		return "RequestClientCert", nil
	case tls.RequireAnyClientCert:
		return "RequireAnyClientCert", nil
	case tls.VerifyClientCertIfGiven:
		return "VerifyClientCertIfGiven", nil
	case tls.RequireAndVerifyClientCert:
		return "RequireAndVerifyClientCert", nil
	default:
		return "", errors.New(fmt.Sprintf("error converting unknown authentication value to string [%d]", a))
	}
}

// IntToAuthentication returns a decode hook function that converts an integer to an authentication.
func IntToAuthentication() mapstructure.DecodeHookFunc {

	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {

		if from != reflect.TypeOf("") {
			return data, nil
		}

		if to != reflect.TypeOf(Authentication(0)) {
			return data, nil
		}

		var authentication Authentication

		err := authentication.FromString(data.(string))
		if err != nil {
			return nil, errors.Wrapf(err, "error decoding integer as authentication")
		}

		return authentication, nil
	}
}
