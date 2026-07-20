/*
SPDX-License-Identifier: Apache-2.0

Copyright Contributors to the Submariner project.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package amneziawg

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestIsValidHeaderValue(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "single uint32", value: "123", want: true},
		{name: "valid range", value: "10-20", want: true},
		{name: "equal bounds", value: "5-5", want: true},
		{name: "inverted range", value: "20-10", want: false},
		{name: "non-numeric", value: "foo", want: false},
		{name: "too many parts", value: "1-2-3", want: false},
		{name: "empty", value: "", want: false},
		{name: "trailing dash", value: "10-", want: false},
		{name: "leading dash", value: "-10", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(isValidHeaderValue(tc.value)).To(Equal(tc.want))
		})
	}
}

func TestIsValidInitPacketValue(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "tag form", value: "<r 40>", want: true},
		{name: "byte tag", value: "<b 64>", want: true},
		{name: "even hex", value: "abcd", want: true},
		{name: "uppercase hex", value: "ABCD12", want: true},
		{name: "odd hex", value: "abc", want: false},
		{name: "non-hex", value: "hello", want: false},
		{name: "empty", value: "", want: false},
		{name: "empty tags", value: "<>", want: false},
		{name: "unclosed tag", value: "<r 40", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(isValidInitPacketValue(tc.value)).To(Equal(tc.want))
		})
	}
}

func TestObfuscationFromOptions(t *testing.T) {
	t.Run("defaults when options are empty", func(t *testing.T) {
		g := NewWithT(t)
		obf := obfuscationFromOptions(nil)
		defaults := defaultObfuscation()

		g.Expect(*obf.Jc).To(Equal(*defaults.Jc))
		g.Expect(*obf.H1).To(Equal(*defaults.H1))
		g.Expect(*obf.I1).To(Equal(*defaults.I1))
		g.Expect(*obf.S3).To(Equal(*defaults.S3))
	})

	t.Run("applies valid overrides and keeps untouched defaults", func(t *testing.T) {
		g := NewWithT(t)
		obf := obfuscationFromOptions(map[string]string{
			"jc": "3",
			"h1": "10-20",
			"i1": "<b 64>",
		})

		g.Expect(*obf.Jc).To(Equal(3))
		g.Expect(*obf.H1).To(Equal("10-20"))
		g.Expect(*obf.I1).To(Equal("<b 64>"))
		g.Expect(*obf.S3).To(Equal(35))
		g.Expect(*obf.H2).To(Equal("400000000-480000000"))
	})

	t.Run("ignores invalid values and keeps defaults", func(t *testing.T) {
		g := NewWithT(t)
		defaults := defaultObfuscation()
		obf := obfuscationFromOptions(map[string]string{
			"jc":  "not-a-number",
			"h1":  "20-10",
			"i1":  "oddhex0",
			"s3":  "",
			"xyz": "ignored",
		})

		g.Expect(*obf.Jc).To(Equal(*defaults.Jc))
		g.Expect(*obf.H1).To(Equal(*defaults.H1))
		g.Expect(*obf.I1).To(Equal(*defaults.I1))
		g.Expect(*obf.S3).To(Equal(*defaults.S3))
	})

	t.Run("ignores inverted jmin/jmax and keeps defaults", func(t *testing.T) {
		g := NewWithT(t)
		defaults := defaultObfuscation()
		obf := obfuscationFromOptions(map[string]string{
			"jmin": "200",
			"jmax": "80",
		})

		g.Expect(*obf.Jmin).To(Equal(*defaults.Jmin))
		g.Expect(*obf.Jmax).To(Equal(*defaults.Jmax))
	})

	t.Run("ignores empty option values", func(t *testing.T) {
		g := NewWithT(t)
		defaults := defaultObfuscation()
		obf := obfuscationFromOptions(map[string]string{
			"jc": "",
			"h1": "",
			"i1": "",
		})

		g.Expect(*obf.Jc).To(Equal(*defaults.Jc))
		g.Expect(*obf.H1).To(Equal(*defaults.H1))
		g.Expect(*obf.I1).To(Equal(*defaults.I1))
	})
}
