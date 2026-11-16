package ebpf

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests load the agent's compiled v4 TC programs and run them on
// hand-built IPv4 packets with BPF_PROG_TEST_RUN, the same way
// tcp_reset_kernel_test.go does, and share its helpers.
//
// The programs take the L4 header at a fixed sizeof(struct iphdr). With IP
// options that offset is still inside the IP header, so the values read there
// are not the packet's ports. Such a packet is rejected instead.
//
// There is no v6 equivalent: IPv6 has no ihl, and the v6 switch keys on the
// outer nexthdr, so an extension header produces no L4 match rather than a
// sender-chosen one.

// ipv4OptionsLen is one 32-bit word of IP options, so ihl is 6.
const ipv4OptionsLen = 4

// ipv4Segment is a TCP segment carried in an IPv4 packet whose header geometry
// the test controls.
type ipv4Segment struct {
	src, dst netip.AddrPort
	// optionWords is the number of 32-bit option words, so ihl is 5 plus it.
	optionWords int
}

// packet builds an Ethernet frame carrying s. The option bytes are set to two
// port-shaped values, so a test can tell which bytes a program read.
func (s ipv4Segment) packet() []byte {
	src, dst := s.src.Addr(), s.dst.Addr()

	tcp := make([]byte, tcpHeaderLen)
	binary.BigEndian.PutUint16(tcp[0:], s.src.Port())
	binary.BigEndian.PutUint16(tcp[2:], s.dst.Port())
	tcp[12] = byte(len(tcp)/4) << 4 // data offset, in 32-bit words
	tcp[13] = tcpFlagSyn
	binary.BigEndian.PutUint16(tcp[14:], 64240)
	binary.BigEndian.PutUint16(tcp[16:], tcpChecksum(src, dst, tcp))

	options := make([]byte, s.optionWords*ipv4OptionsLen)
	if len(options) >= 4 {
		// Port-shaped on purpose, and distinct from the real ports in the TCP
		// header below, so a test can tell the two apart.
		binary.BigEndian.PutUint16(options[0:], 8443)
		binary.BigEndian.PutUint16(options[2:], 9091)
	}

	ip := make([]byte, ipv4HeaderLen+len(options))
	ip[0] = byte(4)<<4 | byte(len(ip)/4) // version and ihl, in 32-bit words
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+len(tcp)))
	ip[8], ip[9] = ipTTL, ipProtoTCP
	copy(ip[12:], append(src.AsSlice(), dst.AsSlice()...))
	copy(ip[ipv4HeaderLen:], options)
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))

	frame := binary.BigEndian.AppendUint16(append(append([]byte{}, podMAC...), clientMAC...), ethTypeIPv4)
	return append(append(frame, ip...), tcp...)
}

func TestIPv4HeaderParseKernel(t *testing.T) {
	dir, required := requireBPFKernelTests(t)
	fam := family{"v4", netip.MustParseAddrPort("10.0.0.1:40000"), netip.MustParseAddrPort("10.0.1.2:80"),
		EVENTS_BINARY, TC_EGRESS_BINARY, []string{TC_INGRESS_BINARY, TC_INGRESS_CT_DENY_BINARY}}

	variants := fam.ingressBinaries
	if err := checkKfuncs(ctDenyKfuncs); err != nil {
		if required {
			t.Fatalf("kernel lacks the conntrack kfuncs the ct-deny variants need (modprobe nf_conntrack): %v", err)
		}
		t.Logf("skipping %s: kernel lacks the conntrack kfuncs: %v", variants[1], err)
		variants = variants[:1]
	}

	cases := []struct {
		name    string
		segment func(src, dst netip.AddrPort) ipv4Segment
		verdict uint32
	}{
		{
			name: "no options: evaluated normally",
			segment: func(src, dst netip.AddrPort) ipv4Segment {
				return ipv4Segment{src: src, dst: dst}
			},
			verdict: tcActOK,
		},
		{
			name: "IP options: rejected before the ports are read",
			segment: func(src, dst netip.AddrPort) ipv4Segment {
				return ipv4Segment{src: src, dst: dst, optionWords: 1}
			},
			verdict: tcActShot,
		},
	}

	for _, ingressBinary := range variants {
		t.Run(ingressBinary, func(t *testing.T) {
			progs := loadFamily(t, dir, fam, ingressBinary)
			// loadFamily denies by default, which drops a packet for the same
			// verdict this change does. Allow instead, so a TC_ACT_SHOT is
			// unambiguously the header check and TC_ACT_OK is a packet that
			// reached policy evaluation.
			writePodState(t, progs.ingressPodState, POD_STATE_MAP_KEY, DEFAULT_ALLOW)
			writePodState(t, progs.egressPodState, POD_STATE_MAP_KEY, DEFAULT_ALLOW)
			// Keep the RST answer off, so a rejected packet is a plain drop
			// rather than TC_ACT_REDIRECT.
			require.NoError(t, writeTCConfig(progs.config, false))

			directions := []struct {
				name     string
				progFD   int
				src, dst netip.AddrPort
			}{
				{"ingress", progs.ingressFD, fam.client, fam.pod},
				{"egress", progs.egressFD, fam.pod, fam.client},
			}
			for _, d := range directions {
				for _, tc := range cases {
					t.Run(d.name+"/"+tc.name, func(t *testing.T) {
						clearMap(t, progs.conntrack)
						verdict, _ := testRun(t, d.progFD, tc.segment(d.src, d.dst).packet())
						require.Equal(t, tc.verdict, verdict)
						if tc.verdict == tcActShot {
							// A rejected packet must not leave a flow behind:
							// an entry keyed on ports read from the wrong
							// offset would fast-path later packets on a tuple
							// that was never evaluated.
							assert.Zero(t, countEntries(t, progs.conntrack), "no flow recorded for a rejected packet")
						}
					})
				}
			}
		})
	}
}
