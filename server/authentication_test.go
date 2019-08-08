package server

import (
	"encoding/json"
	"testing"
	"testing/quick"

	"gopkg.in/yaml.v2"

	"github.com/deciphernow/nautls/internal/tests"
	"github.com/mitchellh/mapstructure"

	. "github.com/smartystreets/goconvey/convey"
)

// MustMarshalJSON marshals an authentication to a JSON byte array or fails the test.
func MustMarshalJSON(authentication Authentication, t *testing.T) []byte {
	bytes, err := json.Marshal(authentication)
	if err != nil {
		t.Fatalf("error marshalling authentication to json [%s]", err.Error())
	}
	return bytes
}

// MustMarshalYAML marshals an authentication to a YAML byte array or fails the test.
func MustMarshalYAML(authentication Authentication, t *testing.T) []byte {
	bytes, err := yaml.Marshal(authentication)
	if err != nil {
		t.Fatalf("error marshalling authentication to yaml [%s]", err.Error())
	}
	return bytes
}

// MustUnmarshalJSON unmarshals an authentication from a JSON byte array or fails the test.
func MustUnmarshalJSON(bytes []byte, t *testing.T) Authentication {
	var authentication Authentication
	err := json.Unmarshal(bytes, &authentication)
	if err != nil {
		t.Fatalf("error unmarshalling authentication from json [%s]", err.Error())
	}
	return authentication
}

// MustUnmarshalYAML unmarshals an authentication from a YAML byte array or fails the test.
func MustUnmarshalYAML(bytes []byte, t *testing.T) Authentication {
	var authentication Authentication
	err := yaml.Unmarshal(bytes, &authentication)
	if err != nil {
		t.Fatalf("error unmarshalling authentication from yaml [%s]", err.Error())
	}
	return authentication
}

func TestAuthentication(t *testing.T) {

	Convey("When authentication.", t, func() {

		Convey("#IntToAuthentication is invoked", func() {

			var actual Authentication

			Convey("without the decode hook registered", func() {

				Convey("with a valid authentication", func() {

					value, err := MustGenerateAuthentication(t).ToString()
					if err != nil {
						t.Fatalf("error raised converting valid authentication to string [%s]", err.Error())
					}

					err = mapstructure.Decode(value, &actual)

					Convey("it should return a non-nil error", func() {
						So(err, ShouldNotBeNil)
					})

					Convey("the authentication should be zeroed", func() {
						So(actual, ShouldBeZeroValue)
					})
				})
			})

			Convey("with the decode hook registered", func() {

				config := &mapstructure.DecoderConfig{DecodeHook: IntToAuthentication(), Result: &actual}

				decoder, err := mapstructure.NewDecoder(config)
				if err != nil {
					t.Fatalf("error initializing decoder [%s]", err.Error())
				}

				Convey("with an invalid value", func() {

					value := tests.MustGenerateString(t)
					err := decoder.Decode(value)

					Convey("it should return a non-nil error", func() {
						So(err, ShouldNotBeNil)
					})

					Convey("the authentication should be zeroed", func() {
						So(actual, ShouldBeZeroValue)
					})
				})

				Convey("with a valid authentication", func() {

					expected := MustGenerateAuthentication(t)
					value, err := expected.ToString()
					if err != nil {
						t.Fatalf("error raised converting valid authentication to string [%s]", err.Error())
					}

					err = decoder.Decode(value)

					Convey("it should return a nil error", func() {
						So(err, ShouldBeNil)
					})

					Convey("the authentication equal the expected value", func() {
						So(actual, ShouldEqual, expected)
					})
				})
			})
		})

		Convey(".Authentication", func() {

			Convey(".MarshalJSON is invoked", func() {

				Convey("on an invalid value", func() {

					invalid := Authentication(tests.MustGenerateInt(t))
					bytes, err := json.Marshal(invalid)

					Convey("it returns a non-nil error", func() {
						So(err, ShouldNotBeNil)
					})

					Convey("it returns a nil byte slice", func() {
						So(bytes, ShouldBeNil)
					})

				})
			})

			Convey(".UnmarshalJSON is invoked", func() {

				Convey("on an invalid type", func() {

					var authentication Authentication

					invalid := []byte("[]")
					err := json.Unmarshal(invalid, &authentication)

					Convey("it returns a non-nil error", func() {
						So(err, ShouldNotBeNil)
					})

					Convey("it returns a zero authentication", func() {
						So(authentication, ShouldBeZeroValue)
					})
				})

				Convey("on an invalid string", func() {

					var authentication Authentication

					invalid := []byte(tests.MustGenerateString(t))
					err := json.Unmarshal(invalid, &authentication)

					Convey("it returns a non-nil error", func() {
						So(err, ShouldNotBeNil)
					})

					Convey("it returns a zero authentication", func() {
						So(authentication, ShouldBeZeroValue)
					})
				})

				Convey("on the output of .MarshalJSON", func() {

					expected := func(a Authentication) Authentication { return a }
					actual := func(a Authentication) Authentication { return MustUnmarshalJSON(MustMarshalJSON(a, t), t) }

					Convey("the input is the same as the output", func() {
						So(quick.CheckEqual(actual, expected, nil), ShouldBeNil)
					})
				})
			})

			Convey(".MarshalYAML is invoked", func() {

				Convey("on an invalid value", func() {

					invalid := Authentication(tests.MustGenerateInt(t))
					bytes, err := yaml.Marshal(invalid)

					Convey("it returns a non-nil error", func() {
						So(err, ShouldNotBeNil)
					})

					Convey("it returns a nil byte slice", func() {
						So(bytes, ShouldBeNil)
					})
				})
			})

			Convey(".UnmarshalYAML is invoked", func() {

				Convey("on an invalid type", func() {

					var authentication Authentication

					invalid := []byte("[]")
					err := yaml.Unmarshal(invalid, &authentication)

					Convey("it returns a non-nil error", func() {
						So(err, ShouldNotBeNil)
					})

					Convey("it returns a zero authentication", func() {
						So(authentication, ShouldBeZeroValue)
					})
				})

				Convey("on an invalid string", func() {

					var authentication Authentication

					invalid := []byte(tests.MustGenerateString(t))
					err := yaml.Unmarshal(invalid, &authentication)

					Convey("it returns a non-nil error", func() {
						So(err, ShouldNotBeNil)
					})

					Convey("it returns a zero authentication", func() {
						So(authentication, ShouldBeZeroValue)
					})
				})

				Convey("on the output of .UnmarshalYAML", func() {

					expected := func(a Authentication) Authentication { return a }
					actual := func(a Authentication) Authentication { return MustUnmarshalYAML(MustMarshalYAML(a, t), t) }

					Convey("the input is the same as the output", func() {
						So(quick.CheckEqual(actual, expected, nil), ShouldBeNil)
					})
				})
			})
		})
	})
}
