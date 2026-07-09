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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewGlobalMapsReadinessCheck(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "global_aws_conntrack_map")
	assert.NoError(t, os.WriteFile(present, []byte("x"), 0o644))
	missing := filepath.Join(dir, "does_not_exist")

	tests := []struct {
		name    string
		paths   []string
		wantErr bool
	}{
		{name: "no paths passes", paths: nil, wantErr: false},
		{name: "all present passes", paths: []string{present}, wantErr: false},
		{name: "one missing fails", paths: []string{present, missing}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewGlobalMapsReadinessCheck(tt.paths)(nil)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewBpfFsReadinessCheck(t *testing.T) {
	t.Run("non-existent path fails statfs", func(t *testing.T) {
		err := NewBpfFsReadinessCheck(filepath.Join(t.TempDir(), "nope"))(nil)
		assert.Error(t, err)
	})

	t.Run("regular dir is not bpffs", func(t *testing.T) {
		// A normal tmpfs/ext4 dir has a non-BPF_FS_MAGIC fs type, so the
		// check must reject it. This is the realistic "bpffs failed to mount,
		// agent is pinning into the root fs" failure mode.
		err := NewBpfFsReadinessCheck(t.TempDir())(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not a bpffs mount")
	})
}
