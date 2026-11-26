package ebpf

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"

	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover what the v4 programs make of a fragmented packet, using
// the tcp_reset_kernel_test.go helpers.
//
// Only the first fragment of a datagram carries the L4 header. A fragment with
// a non-zero offset carries payload at the offset the programs read the ports
// from, so the values there are not ports. They are zeroed rather than dropped:
// ports of 0 match only a rule that applies to any port, so the fragment still
// reaches a peer that policy allows on any port, while dropping it would lose
// the whole datagram, which the receiver cannot reassemble without it.

const (
	// fragOffMF is the more-fragments flag with offset 0, a first fragment.
	fragOffMF = 0x2000
	// fragOffNonFirst is an offset of one 8-byte unit, a later fragment.
	fragOffNonFirst = 0x0001
	// payloadSrcPort and payloadDstPort are the first four payload bytes of a
	// later fragment here, shaped like ports so a test can tell which bytes a
	// program read.
	payloadSrcPort = 8443
	payloadDstPort = 9091
)

// ipv4Fragment is an IPv4 packet whose fragmentation the test controls.
type ipv4Fragment struct {
	src, dst netip.AddrPort
	// fragOff is written to ip->frag_off as is.
	fragOff uint16
	// payloadAtL4 fills the bytes after the IP header with payload whose first
	// four are port-shaped, as a later fragment carries, instead of a TCP
	// header.
	payloadAtL4 bool
}

func (s ipv4Fragment) packet() []byte {
	src, dst := s.src.Addr(), s.dst.Addr()

	l4 := make([]byte, tcpHeaderLen)
	if s.payloadAtL4 {
		binary.BigEndian.PutUint16(l4[0:], payloadSrcPort)
		binary.BigEndian.PutUint16(l4[2:], payloadDstPort)
		// Byte 13 of a TCP header holds the flags. Set here so the deny-time
		// helpers' own selection is exercised.
		l4[13] = tcpFlagSyn
	} else {
		binary.BigEndian.PutUint16(l4[0:], s.src.Port())
		binary.BigEndian.PutUint16(l4[2:], s.dst.Port())
		l4[12] = byte(len(l4)/4) << 4 // data offset, in 32-bit words
		l4[13] = tcpFlagSyn
		binary.BigEndian.PutUint16(l4[14:], 64240)
		binary.BigEndian.PutUint16(l4[16:], tcpChecksum(src, dst, l4))
	}

	ip := make([]byte, ipv4HeaderLen)
	ip[0] = ipv4VersionIHL
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+len(l4)))
	binary.BigEndian.PutUint16(ip[6:], s.fragOff)
	ip[8], ip[9] = ipTTL, ipProtoTCP
	copy(ip[12:], append(src.AsSlice(), dst.AsSlice()...))
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))

	frame := binary.BigEndian.AppendUint16(append(append([]byte{}, podMAC...), clientMAC...), ethTypeIPv4)
	return append(append(frame, ip...), l4...)
}

// recordedPorts returns the ports of the one flow the programs recorded, which
// is how the test sees which bytes they took the ports from.
func recordedPorts(t *testing.T, m goebpfmaps.BpfMap) (src, dst uint16) {
	t.Helper()
	keys, err := m.GetAllMapKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1, "exactly one flow recorded")
	var key utils.ConntrackKey
	raw := []byte(keys[0])
	require.Len(t, raw, int(unsafe.Sizeof(key)), "conntrack key size")
	copy((*[unsafe.Sizeof(key)]byte)(unsafe.Pointer(&key))[:], raw)
	return key.Source_port, key.Dest_port
}

func TestIPv4FragmentPortsKernel(t *testing.T) {
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

	for _, ingressBinary := range variants {
		t.Run(ingressBinary, func(t *testing.T) {
			progs := loadFamily(t, dir, fam, ingressBinary)
			// Allow, so the packet reaches policy evaluation and records a
			// flow whose key the test can read. A denied packet records none.
			writePodState(t, progs.ingressPodState, POD_STATE_MAP_KEY, DEFAULT_ALLOW)
			writePodState(t, progs.egressPodState, POD_STATE_MAP_KEY, DEFAULT_ALLOW)
			require.NoError(t, writeTCConfig(progs.config, false))

			for _, d := range []struct {
				name     string
				progFD   int
				src, dst netip.AddrPort
			}{
				{"ingress", progs.ingressFD, fam.client, fam.pod},
				{"egress", progs.egressFD, fam.pod, fam.client},
			} {
				t.Run(d.name+"/later fragment: ports zeroed, not taken from the payload", func(t *testing.T) {
					clearMap(t, progs.conntrack)
					frag := ipv4Fragment{src: d.src, dst: d.dst, fragOff: fragOffNonFirst, payloadAtL4: true}
					verdict, _ := testRun(t, d.progFD, frag.packet())
					// Still delivered: the pod's rule applies to any port.
					require.Equal(t, uint32(tcActOK), verdict)
					src, dst := recordedPorts(t, progs.conntrack)
					assert.Zero(t, src, "source port not taken from the payload")
					assert.Zero(t, dst, "dest port not taken from the payload")
				})

				t.Run(d.name+"/first fragment: real ports parsed", func(t *testing.T) {
					clearMap(t, progs.conntrack)
					frag := ipv4Fragment{src: d.src, dst: d.dst, fragOff: fragOffMF}
					verdict, _ := testRun(t, d.progFD, frag.packet())
					require.Equal(t, uint32(tcActOK), verdict)
					src, dst := recordedPorts(t, progs.conntrack)
					assert.Equal(t, d.src.Port(), src)
					assert.Equal(t, d.dst.Port(), dst)
				})

				t.Run(d.name+"/unfragmented: real ports parsed", func(t *testing.T) {
					clearMap(t, progs.conntrack)
					frag := ipv4Fragment{src: d.src, dst: d.dst}
					verdict, _ := testRun(t, d.progFD, frag.packet())
					require.Equal(t, uint32(tcActOK), verdict)
					src, dst := recordedPorts(t, progs.conntrack)
					assert.Equal(t, d.src.Port(), src)
					assert.Equal(t, d.dst.Port(), dst)
				})
			}

			// deny_verdict_v4 and shorten_denied_syn_v4 re-read the packet at
			// the same fixed offset rather than reusing the program's parse, so
			// they rely on the same layout and need the same check.
			t.Run("denied later fragment is dropped, not answered with a RST", func(t *testing.T) {
				clearMap(t, progs.conntrack)
				clearMap(t, progs.pending)
				writePodState(t, progs.ingressPodState, POD_STATE_MAP_KEY, DEFAULT_DENY)
				defer writePodState(t, progs.ingressPodState, POD_STATE_MAP_KEY, DEFAULT_ALLOW)
				require.NoError(t, writeTCConfig(progs.config, true))
				defer func() { require.NoError(t, writeTCConfig(progs.config, false)) }()

				frag := ipv4Fragment{src: fam.client, dst: fam.pod, fragOff: fragOffNonFirst, payloadAtL4: true}
				verdict, _ := testRun(t, progs.ingressFD, frag.packet())
				require.Equal(t, uint32(tcActShot), verdict, "dropped, not answered")
				assert.Zero(t, countEntries(t, progs.pending), "no pending RST recorded")
			})
		})
	}
}
