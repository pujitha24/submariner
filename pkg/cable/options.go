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

package cable

import (
	"encoding/json"
	"os"
)

// CableDriverOptionsEnv is set by the operator from Submariner.spec.cableDriverOptions.
const CableDriverOptionsEnv = "SUBMARINER_CABLE_DRIVER_OPTIONS"

// GetDriverOptions returns driver-specific options from the environment.
// An empty or invalid value yields an empty map.
func GetDriverOptions() map[string]string {
	raw := os.Getenv(CableDriverOptionsEnv)
	if raw == "" {
		return map[string]string{}
	}

	options := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &options); err != nil {
		logger.Warningf("Ignoring invalid %s value: %v", CableDriverOptionsEnv, err)
		return map[string]string{}
	}

	return options
}
