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
	"strconv"
	"strings"

	"github.com/advanced-wg/awgctrl-go/wgtypes"
	"github.com/submariner-io/submariner/pkg/cable"
)

// Default AmneziaWG v2 obfuscation parameters used when cable driver options are unset.
// H1–H4 and S1–S4 MUST be identical on every peer; Jc/I* may differ but defaults stay symmetric.
func defaultObfuscation() wgtypes.Config {
	return wgtypes.Config{
		// Junk packets before each handshake (helps break WG size signatures).
		Jc:   intPtr(7),
		Jmin: intPtr(80),
		Jmax: intPtr(200),

		// Message padding (AWG 2.0: S3 cookie, S4 transport).
		S1: intPtr(45),
		S2: intPtr(60),
		S3: intPtr(35),
		S4: intPtr(12),

		// Magic headers as non-overlapping ranges (AWG 2.0) — not the fixed WG types 1–4.
		H1: strPtr("200000000-280000000"),
		H2: strPtr("400000000-480000000"),
		H3: strPtr("600000000-680000000"),
		H4: strPtr("800000000-880000000"),

		// Custom init packets (AWG 2.0) — random-looking UDP before handshake.
		I1: strPtr("<r 40>"),
		I2: strPtr("<r 25>"),
		I3: strPtr("<r 20>"),
		I4: strPtr("<r 15>"),
		I5: strPtr("<r 15>"),
	}
}

func applyObfuscation(cfg *wgtypes.Config, options map[string]string) {
	obf := obfuscationFromOptions(options)

	cfg.Jc = obf.Jc
	cfg.Jmin = obf.Jmin
	cfg.Jmax = obf.Jmax
	cfg.S1 = obf.S1
	cfg.S2 = obf.S2
	cfg.S3 = obf.S3
	cfg.S4 = obf.S4
	cfg.H1 = obf.H1
	cfg.H2 = obf.H2
	cfg.H3 = obf.H3
	cfg.H4 = obf.H4
	cfg.I1 = obf.I1
	cfg.I2 = obf.I2
	cfg.I3 = obf.I3
	cfg.I4 = obf.I4
	cfg.I5 = obf.I5
}

func applyCableDriverObfuscation(cfg *wgtypes.Config) {
	applyObfuscation(cfg, cable.GetDriverOptions())
}

func obfuscationFromOptions(options map[string]string) wgtypes.Config {
	obf := defaultObfuscation()
	if len(options) == 0 {
		return obf
	}

	setIntOption(options, "jc", &obf.Jc)
	setIntOption(options, "jmin", &obf.Jmin)
	setIntOption(options, "jmax", &obf.Jmax)
	setIntOption(options, "s1", &obf.S1)
	setIntOption(options, "s2", &obf.S2)
	setIntOption(options, "s3", &obf.S3)
	setIntOption(options, "s4", &obf.S4)

	setHeaderOption(options, "h1", &obf.H1)
	setHeaderOption(options, "h2", &obf.H2)
	setHeaderOption(options, "h3", &obf.H3)
	setHeaderOption(options, "h4", &obf.H4)
	setInitPacketOption(options, "i1", &obf.I1)
	setInitPacketOption(options, "i2", &obf.I2)
	setInitPacketOption(options, "i3", &obf.I3)
	setInitPacketOption(options, "i4", &obf.I4)
	setInitPacketOption(options, "i5", &obf.I5)

	return obf
}

func setIntOption(options map[string]string, key string, dest **int) {
	value, ok := options[key]
	if !ok || value == "" {
		return
	}

	n, err := strconv.Atoi(value)
	if err != nil {
		logger.Warningf("Ignoring invalid AmneziaWG option %q=%q: %v", key, value, err)
		return
	}

	*dest = intPtr(n)
}

func setHeaderOption(options map[string]string, key string, dest **string) {
	value, ok := options[key]
	if !ok || value == "" {
		return
	}

	if !isValidHeaderValue(value) {
		logger.Warningf("Ignoring invalid AmneziaWG option %q=%q: expected uint32 or min-max range", key, value)
		return
	}

	*dest = strPtr(value)
}

func setInitPacketOption(options map[string]string, key string, dest **string) {
	value, ok := options[key]
	if !ok || value == "" {
		return
	}

	if !isValidInitPacketValue(value) {
		logger.Warningf("Ignoring invalid AmneziaWG option %q=%q: expected <tag ...> or hex bytes", key, value)
		return
	}

	*dest = strPtr(value)
}

// isValidHeaderValue accepts a single uint32 or a non-inverted "min-max" range.
func isValidHeaderValue(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return false
	}

	nums := make([]uint64, 0, len(parts))

	for _, part := range parts {
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return false
		}

		nums = append(nums, n)
	}

	if len(nums) == 2 && nums[0] > nums[1] {
		return false
	}

	return true
}

// isValidInitPacketValue accepts Amnezia custom-packet tags (<r N>, <b N>, …)
// or an even-length hex payload.
func isValidInitPacketValue(value string) bool {
	if strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">") && len(value) > 2 {
		return true
	}

	if len(value) == 0 || len(value)%2 != 0 {
		return false
	}

	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}

	return true
}

func intPtr(i int) *int {
	return &i
}

func strPtr(s string) *string {
	return &s
}
