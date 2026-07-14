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

	"golang.org/x/sys/unix"
)

// BPF_FS_ROOT is the mount point the agent pins its programs and maps under.
const BPF_FS_ROOT = "/sys/fs/bpf"

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

// NewBpfFsReadinessCheck returns a readiness check that verifies the BPF
// filesystem at root is mounted as bpffs and is not mounted read-only. Without
// a writable bpffs the agent cannot pin programs or maps, so it should not be
// reported ready even if the process and gRPC server are up.
func NewBpfFsReadinessCheck(root string) func(_ *http.Request) error {
	return func(_ *http.Request) error {
		var st unix.Statfs_t
		if err := unix.Statfs(root, &st); err != nil {
			err = fmt.Errorf("statfs %s failed: %w", root, err)
			log().Errorf("bpf-fs check failed: %v", err)
			return err
		}
		if st.Type != unix.BPF_FS_MAGIC {
			err := fmt.Errorf("%s is not a bpffs mount (fs magic 0x%x)", root, st.Type)
			log().Errorf("bpf-fs check failed: %v", err)
			return err
		}
		if st.Flags&unix.ST_RDONLY != 0 {
			err := fmt.Errorf("bpf filesystem at %s is mounted read-only", root)
			log().Errorf("bpf-fs check failed: %v", err)
			return err
		}
		return nil
	}
}
