package aws

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCloud_ValidationErrors(t *testing.T) {
	tests := []struct {
		name       string
		region     string
		instanceID string
		wantErr    string
	}{
		{
			name:       "missing region",
			instanceID: "i-0123456789abcdef0",
			wantErr:    "region not provided; cannot initialize AWS session for CloudWatch logs",
		},
		{
			name:    "missing instance ID",
			region:  "us-west-2",
			wantErr: "instance ID not provided; cannot resolve cluster name for CloudWatch logs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cloud, err := NewCloud(context.Background(), tt.region, tt.instanceID)
			assert.EqualError(t, err, tt.wantErr)
			assert.Nil(t, cloud)
		})
	}
}
