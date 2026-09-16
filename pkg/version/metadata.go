/*
Copyright 2026.

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

package version

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const (
	metadataSchemaVersion = 1
	metadataComponent     = "aws-network-policy-agent"
	maxMetadataSize       = 8 * 1024
)

type metadata struct {
	SchemaVersion  int    `json:"schemaVersion"`
	Component      string `json:"component"`
	Version        string `json:"version"`
	GitCommit      string `json:"gitCommit"`
	BuildDate      string `json:"buildDate"`
	GoVersion      string `json:"goVersion"`
	Platform       string `json:"platform"`
	EbpfSDKVersion string `json:"ebpfSdkVersion"`
}

type metadataWriter func(string) error

// PublishMetadataAsync starts one best-effort metadata publication attempt.
// Publication never delays network policy agent startup.
func PublishMetadataAsync(path string, errorOutput io.Writer) {
	publishMetadataAsync(path, errorOutput, writeMetadata)
}

func publishMetadataAsync(path string, errorOutput io.Writer, writer metadataWriter) {
	go func() {
		if err := writer(path); err != nil {
			_, _ = fmt.Fprintf(errorOutput, "warning: failed to publish AWS network policy agent metadata: %v\n", err)
		}
	}()
}

func writeMetadata(path string) error {
	data, err := marshalMetadata()
	if err != nil {
		return err
	}

	tempFile, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create metadata temporary file: %w", err)
	}
	tempPath := tempFile.Name()
	defer func() {
		_ = tempFile.Close()
		_ = os.Remove(tempPath)
	}()

	bytesWritten, err := tempFile.Write(data)
	if err != nil {
		return fmt.Errorf("write metadata temporary file: %w", err)
	}
	if bytesWritten != len(data) {
		return fmt.Errorf("write metadata temporary file: wrote %d of %d bytes", bytesWritten, len(data))
	}
	if err := tempFile.Chmod(0o644); err != nil {
		return fmt.Errorf("set metadata file mode: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close metadata temporary file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace metadata file: %w", err)
	}
	return nil
}

func marshalMetadata() ([]byte, error) {
	record := metadata{
		SchemaVersion:  metadataSchemaVersion,
		Component:      metadataComponent,
		Version:        valueOrUnknown(GitVersion),
		GitCommit:      valueOrUnknown(GitCommit),
		BuildDate:      valueOrUnknown(BuildDate),
		GoVersion:      runtime.Version(),
		Platform:       runtime.GOOS + "/" + runtime.GOARCH,
		EbpfSDKVersion: valueOrUnknown(EbpfSDKVersion),
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxMetadataSize {
		return nil, fmt.Errorf("metadata exceeds %d bytes", maxMetadataSize)
	}
	return data, nil
}

func valueOrUnknown(value string) string {
	return cmp.Or(value, "unknown")
}
