package ipfilter

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("dns", `ipfilter`)
	if err := SetupIPFilter(c); err != nil {
		t.Fatalf("Expected no errors, but got: %v", err)
	}

	c = caddy.NewTestController("dns", `ipfilter any_random_arg`)
	if err := SetupIPFilter(c); err == nil {
		t.Fatalf("Expected errors, but got: %v", err)
	}
}
