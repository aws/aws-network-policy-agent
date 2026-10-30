package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"unsafe"
)

// Verifies the unsafe struct view + netip formatting produce identical results
// to the old binary.Read-based decode path.
func TestDecodeMatchesLegacy(t *testing.T) {
	// Pin the Go struct to the C struct data_t layout (sizeof 32).
	if got := unsafe.Sizeof(ringBufferDataV4_t{}); got != 32 {
		t.Fatalf("ringBufferDataV4_t size = %d, want 32 (must match C struct data_t)", got)
	}
	// raw sample as the bpf program writes it: struct data_t, little-endian fields
	src := ringBufferDataV4_t{
		SourceIP:   0x0501a8c0, // 192.168.1.5 in wire order read LE
		SourcePort: 54321,
		DestIP:     0x0201a8c0, // 192.168.1.2
		DestPort:   80,
		Protocol:   17,
		Verdict:    0,
		PacketSz:   64,
		IsEgress:   1,
		Tier:       2,
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &src); err != nil {
		t.Fatal(err)
	}
	// RawSample carries the C struct data_t (30 bytes of fields, sizeof 32
	// with trailing padding); allocate the padded size.
	raw := make([]byte, 32)
	copy(raw, buf.Bytes())

	// legacy decode
	var legacy ringBufferDataV4_t
	if err := binary.Read(bytes.NewBuffer(raw), binary.LittleEndian, &legacy); err != nil {
		t.Fatal(err)
	}
	// new decode
	got := (*ringBufferDataV4_t)(unsafe.Pointer(&raw[0]))
	if *got != legacy {
		t.Fatalf("struct mismatch: got %+v want %+v", *got, legacy)
	}
	// IP formatting parity
	// IP fields hold the packet's big-endian bytes read as a little-endian
	// u32. Cases include leading-zero octets.
	for v, want := range map[uint32]string{
		src.SourceIP: "192.168.1.5",
		src.DestIP:   "192.168.1.2",
		0xffffffff:   "255.255.255.255",
		0x0100007f:   "127.0.0.1",
		0x01000000:   "0.0.0.1",
		0x00000001:   "1.0.0.0",
		0:            "0.0.0.0",
	} {
		if got := ipv4Str(v); got != want {
			t.Fatalf("ip mismatch for %#x: got %s want %s", v, got, want)
		}
	}
}

// Verifies formatFlowLine output is byte-identical to the previous
// fmt-based Infof format string.
func TestFormatFlowLineParity(t *testing.T) {
	got := formatFlowLine(false, "192.168.1.5", 54321, "10.0.0.2", 80, "TCP", "DENY", "egress", "NETWORK_POLICY")
	want := fmt.Sprintf("Flow Info: Src IP: %s Src Port: %d Dest IP: %s Dest Port: %d Proto %s Verdict %s Direction %s, Tier %s",
		"192.168.1.5", 54321, "10.0.0.2", 80, "TCP", "DENY", "egress", "NETWORK_POLICY")
	if got != want {
		t.Fatalf("v4 format mismatch:\ngot  %q\nwant %q", got, want)
	}

	// The legacy v6 path used a different format string (colons, no comma).
	got = formatFlowLine(true, "2600:1f14::5", 54321, "2600:1f14::2", 80, "TCP", "DENY", "egress", "NETWORK_POLICY")
	want = fmt.Sprintf("Flow Info: Src IP: %s Src Port: %d Dest IP: %s Dest Port: %d Proto: %s Verdict: %s Direction: %s Tier: %s",
		"2600:1f14::5", 54321, "2600:1f14::2", 80, "TCP", "DENY", "egress", "NETWORK_POLICY")
	if got != want {
		t.Fatalf("v6 format mismatch:\ngot  %q\nwant %q", got, want)
	}
}

// ipv6Str must match the legacy net.IP.String() rendering, including
// v4-mapped addresses rendering as dotted-quad.
func TestIPv6StrParity(t *testing.T) {
	cases := [][16]byte{
		{0x26, 0x00, 0x1f, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05}, // plain v6
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1},         // v4-mapped
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},                // ::1
	}
	for _, c := range cases {
		legacy := net.IP(c[:]).String()
		if got := ipv6Str(c); got != legacy {
			t.Fatalf("ipv6 render mismatch for %v: got %q legacy %q", c, got, legacy)
		}
	}
}

// Same as TestDecodeMatchesLegacy for the v6 record layout (sizeof 56).
func TestDecodeV6MatchesLegacy(t *testing.T) {
	if got := unsafe.Sizeof(ringBufferDataV6_t{}); got != 56 {
		t.Fatalf("ringBufferDataV6_t size = %d, want 56 (must match C struct data_t)", got)
	}
	src := ringBufferDataV6_t{
		SourceIP:   [16]byte{0x26, 0x00, 0x1f, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5},
		SourcePort: 54321,
		DestIP:     [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1},
		DestPort:   80,
		Protocol:   6,
		Verdict:    1,
		PacketSz:   1500,
		IsEgress:   0,
		Tier:       1,
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &src); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 56)
	copy(raw, buf.Bytes())

	var legacy ringBufferDataV6_t
	if err := binary.Read(bytes.NewBuffer(raw), binary.LittleEndian, &legacy); err != nil {
		t.Fatal(err)
	}
	got := (*ringBufferDataV6_t)(unsafe.Pointer(&raw[0]))
	if *got != legacy {
		t.Fatalf("struct mismatch: got %+v want %+v", *got, legacy)
	}
}
