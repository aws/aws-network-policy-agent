package upgrade

import "testing"

// Plain Go tests for the helpers that decide the expectations. They need no
// cluster: run with `go test ./test/integration/upgrade -run 'TestDiffBinaries|TestParseSHA256Sums|TestProgDirection'`.

func TestDiffBinaries(t *testing.T) {
	base := map[string]string{
		"tc.v4ingress.bpf.o": "aa",
		"tc.v4egress.bpf.o":  "bb",
		"v4events.bpf.o":     "cc",
		"tc.shared.bpf.o":    "ee",
	}
	with := func(name, hash string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		if hash == "" {
			delete(m, name)
		} else {
			m[name] = hash
		}
		return m
	}

	tests := []struct {
		name  string
		after map[string]string
		want  binaryChanges
	}{
		{"nothing changed", base, binaryChanges{}},
		{"ingress only", with("tc.v4ingress.bpf.o", "xx"), binaryChanges{ingress: true}},
		{"egress only", with("tc.v4egress.bpf.o", "xx"), binaryChanges{egress: true}},
		{"events reloads everything", with("v4events.bpf.o", "xx"), binaryChanges{ingress: true, egress: true, events: true}},
		{"shared reloads both directions", with("tc.shared.bpf.o", "xx"), binaryChanges{ingress: true, egress: true, shared: true}},
		{"shared on one side only counts as changed", with("tc.shared.bpf.o", ""), binaryChanges{ingress: true, egress: true, shared: true}},
		{"missing file counts as changed", with("tc.v4egress.bpf.o", ""), binaryChanges{egress: true}},
		{"new file counts as changed", with("tc.v6ingress.bpf.o", "dd"), binaryChanges{ingress: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := diffBinaries(base, tt.after)
			if err != nil {
				t.Fatalf("diffBinaries() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("diffBinaries() = %+v, want %+v", got, tt.want)
			}
		})
	}

	t.Run("unknown changed binary is an error", func(t *testing.T) {
		if _, err := diffBinaries(base, with("tc.future.bpf.o", "ff")); err == nil {
			t.Error("diffBinaries() accepted a changed binary it cannot classify")
		}
	})
	t.Run("unknown unchanged binary is fine", func(t *testing.T) {
		b := with("tc.future.bpf.o", "ff")
		if _, err := diffBinaries(b, b); err != nil {
			t.Errorf("diffBinaries() error = %v", err)
		}
	})
}

func TestParseSHA256Sums(t *testing.T) {
	h1 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	h2 := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	out := h1 + "  tc.v4ingress.bpf.o\n" + h2 + " *v4events.bpf.o\n\n"

	got, err := parseSHA256Sums(out)
	if err != nil {
		t.Fatalf("parseSHA256Sums() error = %v", err)
	}
	if len(got) != 2 || got["tc.v4ingress.bpf.o"] != h1 || got["v4events.bpf.o"] != h2 {
		t.Errorf("parseSHA256Sums() = %v", got)
	}

	if _, err := parseSHA256Sums("sha256sum: *.bpf.o: No such file or directory"); err == nil {
		t.Error("parseSHA256Sums() accepted an error message as output")
	}
}

func TestProgDirection(t *testing.T) {
	for pin, want := range map[string]string{
		"coredns-5d78c9869d@kube-system_handle_ingress": "ingress",
		"coredns-5d78c9869d@kube-system_handle_egress":  "egress",
		"something_else": "",
	} {
		if got := progDirection(pin); got != want {
			t.Errorf("progDirection(%q) = %q, want %q", pin, got, want)
		}
	}
}
