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
	"github.com/advanced-wg/awgctrl-go/wgtypes"
)

// Hardcoded AmneziaWG v2 obfuscation parameters shared by all gateways in the mesh.
// H1–H4 and S1–S4 MUST be identical on every peer; Jc/I* may differ but we keep them
// the same for a symmetric mesh.
// TODO: make these configurable via join/broker/cluster spec.
func hardcodedObfuscation() wgtypes.Config {
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

func applyHardcodedObfuscation(cfg *wgtypes.Config) {
	obf := hardcodedObfuscation()

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

func intPtr(i int) *int {
	return &i
}

func strPtr(s string) *string {
	return &s
}
