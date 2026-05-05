// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package ebpf

import (
	"fmt"
	"net/http"
	"os"
)

// NewGlobalMapsReadinessCheck returns a health check that verifies the given
// BPF map pin paths exist.
func NewGlobalMapsReadinessCheck(paths []string) func(_ *http.Request) error {
	return func(_ *http.Request) error {
		for _, p := range paths {
			if _, err := os.Stat(p); err != nil {
				err = fmt.Errorf("required BPF map pin missing: %s: %w", p, err)
				log().Errorf("bpf-maps check failed: %v", err)
				return err
			}
		}
		return nil
	}
}
