package ebpf

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// These tests load the agent's compiled TC programs into the kernel and run
// them on hand-built packets with BPF_PROG_TEST_RUN, which returns the
// program's verdict and the packet as the program left it. They check that a
// denied SYN becomes a well-formed RST only with the flag on, and that the
// egress program passes that RST without recording a flow.
//
// They need root and the objects from `make build-bpf` (in pkg/ebpf/c, or in
// BPF_OBJECTS_DIR), so they skip under `make test`. CI runs them with
// BPF_KERNEL_TESTS=required, which turns a skip into a failure.

// tcVerdict values (TC_ACT_* in include/uapi/linux/pkt_cls.h), as the
// programs return them.
const (
	tcActOK       = 0
	tcActShot     = 2
	tcActRedirect = 7
)

// testPinPrefix keeps the test's pins apart from an agent's on the same node.
// It has no "_": see ctDenyProbePinPrefix.
const testPinPrefix = "TCPRESETTEST"

// tcpFlag* are the TCP header flag bits (RFC 9293 3.1).
const (
	tcpFlagFin = 0x01
	tcpFlagSyn = 0x02
	tcpFlagRst = 0x04
	tcpFlagAck = 0x10
)

const (
	ethHeaderLen  = 14
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
	tcpHeaderLen  = 20
	// synOptionsLen is a typical SYN's options (MSS, SACK permitted,
	// timestamps, window scale), which the RST must not carry.
	synOptionsLen = 20
	ipProtoTCP    = 6
	ethTypeIPv4   = 0x0800
	ethTypeIPv6   = 0x86dd
	// The first byte of each IP header: version 4 with a 5-word header, and
	// version 6 with traffic class 0.
	ipv4VersionIHL = 0x45
	ipv6Version    = 0x60
	// ipTTL is the Linux default (net.ipv4.ip_default_ttl); the programs
	// don't read it.
	ipTTL = 64
	// packetBufferLen is enough for every packet in these tests.
	packetBufferLen = 256
)

var (
	clientMAC = []byte{0x02, 0, 0, 0, 0, 0x01} // the host veth, as seen by the pod
	podMAC    = []byte{0x02, 0, 0, 0, 0, 0x02}
)

// requireBPFKernelTests returns the directory with the BPF objects, or skips
// the test where it can't run (not root, objects not built). Under
// BPF_KERNEL_TESTS=required a skip fails instead, so CI can't pass without
// running it; it also returns whether that is set. It mounts bpffs if needed,
// since the loader pins every map there.
func requireBPFKernelTests(t *testing.T) (dir string, required bool) {
	t.Helper()
	required = os.Getenv("BPF_KERNEL_TESTS") == "required"
	skip := t.Skipf
	if required {
		skip = t.Fatalf
	}
	if os.Geteuid() != 0 {
		skip("loading BPF programs needs root")
	}
	dir = os.Getenv("BPF_OBJECTS_DIR")
	if dir == "" {
		dir = "c"
	}
	if _, err := os.Stat(filepath.Join(dir, TC_SHARED_BINARY)); err != nil {
		skip("BPF objects not built (make build-bpf): %v", err)
	}
	var fs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &fs); err != nil || fs.Type != unix.BPF_FS_MAGIC {
		require.NoError(t, unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, ""), "mount bpffs")
	}
	t.Cleanup(removeTestPins)
	return dir, required
}

// removeTestPins removes what the test pinned. Left behind, the next run's
// loader would reuse those maps, with their old contents, instead of creating
// fresh ones.
func removeTestPins() {
	for _, dir := range []string{utils.BPF_PROGRAMS_PIN_PATH_DIRECTORY, utils.BPF_MAPS_PIN_PATH_DIRECTORY} {
		pins, _ := filepath.Glob(dir + testPinPrefix + "*_*")
		for _, pin := range pins {
			os.Remove(pin)
		}
	}
}

// family is one address family's test addresses and binaries. The second
// ingress binary is the ct-deny variant.
type family struct {
	name                       string
	client, pod                netip.AddrPort
	eventsBinary, egressBinary string
	ingressBinaries            []string
}

// loadedFamily holds one address family's programs and the maps the tests
// read or write.
type loadedFamily struct {
	ingressFD, egressFD                                         int
	config, pending, conntrack, ingressPodState, egressPodState goebpfmaps.BpfMap
}

// loadFamily loads the events and shared binaries, then ingressBinary and the
// family's egress binary, with both pods' policy state set to default deny.
// The events and shared binaries come first because the TC programs reference
// their maps. Default deny on both sides means every test packet is denied
// without writing any policy, and the egress side is the hardest case for the
// RST: a pod whose own egress denies everything must still get it out.
func loadFamily(t *testing.T, dir string, fam family, ingressBinary string) loadedFamily {
	t.Helper()
	sdk := goelf.New(goelf.Config{NamespacedMaps: utils.NamespacedBPFMaps})
	var fds []int
	t.Cleanup(func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	})
	load := func(binary, pinPrefix string) (progFD int, maps map[string]goebpfmaps.BpfMap) {
		progs, maps, err := sdk.LoadBpfFile(filepath.Join(dir, binary), testPinPrefix+pinPrefix)
		require.NoError(t, err, "load %s", binary)
		for _, p := range progs {
			progFD = p.Program.ProgFD
			fds = append(fds, progFD)
		}
		for _, m := range maps {
			fds = append(fds, int(m.MapFD))
		}
		return progFD, maps
	}
	_, globalMaps := load(fam.eventsBinary, "EVENTS")
	_, sharedMaps := load(TC_SHARED_BINARY, "SHARED")
	ingressFD, ingressMaps := load(ingressBinary, "INGRESS")
	egressFD, egressMaps := load(fam.egressBinary, "EGRESS")
	// No policy applies to the pod, and its namespace denies by default, so
	// every new connection to or from it is denied.
	for _, stateMap := range []goebpfmaps.BpfMap{ingressMaps[utils.TC_INGRESS_POD_STATE_MAP], egressMaps[utils.TC_EGRESS_POD_STATE_MAP]} {
		writePodState(t, stateMap, POD_STATE_MAP_KEY, DEFAULT_DENY)
		writePodState(t, stateMap, CLUSTER_POLICY_POD_STATE_MAP_KEY, DEFAULT_ALLOW)
	}
	return loadedFamily{ingressFD: ingressFD, egressFD: egressFD,
		config: sharedMaps[TC_CONFIG_MAP], pending: sharedMaps[TCP_RESET_PENDING_MAP],
		conntrack: globalMaps[AWS_CONNTRACK_MAP], ingressPodState: ingressMaps[utils.TC_INGRESS_POD_STATE_MAP],
		egressPodState: egressMaps[utils.TC_EGRESS_POD_STATE_MAP]}
}

func writePodState(t *testing.T, stateMap goebpfmaps.BpfMap, key, state int) {
	t.Helper()
	k, value := uint32(key), pod_state{state: uint8(state)}
	require.NoError(t, stateMap.CreateUpdateMapEntry(uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&value)), 0))
}

// testRun runs the program on packet once, the way the kernel would at its
// TC hook, and returns its verdict and the packet it left.
func testRun(t *testing.T, progFD int, packet []byte) (uint32, []byte) {
	t.Helper()
	out := make([]byte, packetBufferLen)
	attr := struct {
		progFD, retval, dataSizeIn, dataSizeOut uint32
		dataIn, dataOut                         uint64
		repeat, duration                        uint32
	}{
		progFD:      uint32(progFD),
		dataSizeIn:  uint32(len(packet)),
		dataSizeOut: uint32(len(out)),
		dataIn:      uint64(uintptr(unsafe.Pointer(&packet[0]))),
		dataOut:     uint64(uintptr(unsafe.Pointer(&out[0]))),
		repeat:      1,
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_TEST_RUN, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	require.Zero(t, errno, "BPF_PROG_TEST_RUN")
	return attr.retval, out[:attr.dataSizeOut]
}

// tcpSegment is a TCP segment and the addresses its checksum covers.
type tcpSegment struct {
	src, dst netip.AddrPort
	seq      uint32
	flags    uint8
}

// packet builds an Ethernet frame from the client to the pod carrying s, with
// synOptionsLen bytes of options because real SYNs carry them, and the RST
// must not: the tests check that the program drops them.
func (s tcpSegment) packet() []byte {
	src, dst := s.src.Addr(), s.dst.Addr()
	tcp := make([]byte, tcpHeaderLen+synOptionsLen)
	binary.BigEndian.PutUint16(tcp[0:], s.src.Port())
	binary.BigEndian.PutUint16(tcp[2:], s.dst.Port())
	binary.BigEndian.PutUint32(tcp[4:], s.seq)
	tcp[12] = byte(len(tcp)/4) << 4 // data offset, in 32-bit words
	tcp[13] = s.flags
	binary.BigEndian.PutUint16(tcp[14:], 64240) // the window Linux advertises in a SYN
	binary.BigEndian.PutUint16(tcp[16:], tcpChecksum(src, dst, tcp))

	ethType, ip := uint16(ethTypeIPv6), make([]byte, ipv6HeaderLen)
	if src.Is4() {
		ethType, ip = ethTypeIPv4, make([]byte, ipv4HeaderLen)
		ip[0] = ipv4VersionIHL
		binary.BigEndian.PutUint16(ip[2:], uint16(ipv4HeaderLen+len(tcp))) // total length
		ip[8], ip[9] = ipTTL, ipProtoTCP
	} else {
		ip[0] = ipv6Version
		binary.BigEndian.PutUint16(ip[4:], uint16(len(tcp))) // payload length
		ip[6], ip[7] = ipProtoTCP, ipTTL                     // next header, hop limit
	}
	// Both IP headers end with the source address, then the destination.
	copy(ip[len(ip)-2*len(src.AsSlice()):], append(src.AsSlice(), dst.AsSlice()...))
	if src.Is4() {
		binary.BigEndian.PutUint16(ip[10:], checksum(ip)) // header checksum
	}
	frame := binary.BigEndian.AppendUint16(append(append([]byte{}, podMAC...), clientMAC...), ethType)
	return append(append(frame, ip...), tcp...)
}

// checksum is the Internet checksum of data. The tests check the program's
// checksums with this independent implementation, so a mistake in the
// program's checksum code shows up as a mismatch. Over a header whose checksum
// field is zero it is the value for that field; over a header with a valid
// checksum it is zero.
func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// tcpChecksum is checksum over segment preceded by the pseudo header of src
// and dst, the part of the TCP checksum input that comes from the IP header
// (RFC 9293 3.1 for IPv4, RFC 8200 8.1 for IPv6).
func tcpChecksum(src, dst netip.Addr, segment []byte) uint16 {
	pseudo := append(src.AsSlice(), dst.AsSlice()...)
	if src.Is4() {
		pseudo = binary.BigEndian.AppendUint16(append(pseudo, 0, ipProtoTCP), uint16(len(segment)))
	} else {
		pseudo = append(binary.BigEndian.AppendUint32(pseudo, uint32(len(segment))), 0, 0, 0, ipProtoTCP)
	}
	return checksum(append(pseudo, segment...))
}

// assertAnsweredWithReset checks that the ingress program answers syn with
// the RST (from the pod back to the client, seq 0, acking syn's seq + 1, no
// options, valid checksums) and that the egress program passes that RST once.
// It returns the ifindex BPF_PROG_TEST_RUN gave the packet, which the programs
// put in their flow and pending keys, read from the pending entry.
func assertAnsweredWithReset(t *testing.T, progs loadedFamily, syn tcpSegment) (ifindex uint32) {
	t.Helper()
	verdict, frame := testRun(t, progs.ingressFD, syn.packet())
	require.Equal(t, uint32(tcActRedirect), verdict)
	ipLen, ethType := ipv6HeaderLen, ethTypeIPv6
	if syn.src.Addr().Is4() {
		ipLen, ethType = ipv4HeaderLen, ethTypeIPv4
	}
	require.Len(t, frame, ethHeaderLen+ipLen+tcpHeaderLen, "RST length")
	assert.Equal(t, clientMAC, frame[0:6], "destination MAC: the host veth")
	assert.Equal(t, podMAC, frame[6:12], "source MAC: the pod")
	assert.Equal(t, uint16(ethType), binary.BigEndian.Uint16(frame[12:]), "EtherType")

	ip, tcp := frame[ethHeaderLen:ethHeaderLen+ipLen], frame[ethHeaderLen+ipLen:]
	if syn.src.Addr().Is4() {
		assert.Equal(t, byte(ipv4VersionIHL), ip[0], "version and header length")
		assert.Equal(t, uint16(ipv4HeaderLen+tcpHeaderLen), binary.BigEndian.Uint16(ip[2:]), "total length")
		assert.Equal(t, byte(ipProtoTCP), ip[9], "protocol")
		assert.Zero(t, checksum(ip), "IPv4 header checksum")
	} else {
		assert.Equal(t, byte(ipv6Version), ip[0], "version")
		assert.Equal(t, uint16(tcpHeaderLen), binary.BigEndian.Uint16(ip[4:]), "payload length")
		assert.Equal(t, byte(ipProtoTCP), ip[6], "next header")
	}
	addrs := ip[len(ip)-2*len(syn.src.Addr().AsSlice()):]
	src, _ := netip.AddrFromSlice(addrs[:len(addrs)/2])
	dst, _ := netip.AddrFromSlice(addrs[len(addrs)/2:])
	assert.Equal(t, syn.dst.Addr(), src, "source: the pod")
	assert.Equal(t, syn.src.Addr(), dst, "destination: the client")
	assert.Equal(t, syn.dst.Port(), binary.BigEndian.Uint16(tcp[0:]), "source port")
	assert.Equal(t, syn.src.Port(), binary.BigEndian.Uint16(tcp[2:]), "destination port")
	assert.Zero(t, binary.BigEndian.Uint32(tcp[4:]), "seq")
	assert.Equal(t, syn.seq+1, binary.BigEndian.Uint32(tcp[8:]), "ack")
	assert.Equal(t, byte(tcpHeaderLen/4)<<4, tcp[12], "data offset")
	assert.Equal(t, byte(tcpFlagRst|tcpFlagAck), tcp[13], "flags")
	assert.Zero(t, tcpChecksum(src, dst, tcp), "TCP checksum")

	assert.Zero(t, countEntries(t, progs.conntrack), "no flow for the denied SYN: a stale one is removed")
	pending, err := progs.pending.GetAllMapKeys()
	require.NoError(t, err)
	if assert.Len(t, pending, 1, "RST recorded for the egress program") {
		key := []byte(pending[0])
		ifindex = binary.NativeEndian.Uint32(key[len(key)-4:]) // the key's last field, a __u32
	}

	// The pod's egress policy denies everything, yet the RST passes, and
	// leaves no flow that would let the client's next SYN in as a reply.
	verdict, _ = testRun(t, progs.egressFD, frame)
	assert.Equal(t, uint32(tcActOK), verdict, "egress passes the RST")
	assert.Zero(t, countEntries(t, progs.pending), "egress consumed the entry")
	assert.Zero(t, countEntries(t, progs.conntrack), "no flow recorded")

	verdict, _ = testRun(t, progs.egressFD, frame)
	assert.Equal(t, uint32(tcActShot), verdict, "a second identical RST is the pod's own and is denied")
	return ifindex
}

// clearMap deletes every entry in m.
func clearMap(t *testing.T, m goebpfmaps.BpfMap) {
	t.Helper()
	keys, err := m.GetAllMapKeys()
	require.NoError(t, err)
	for _, k := range keys {
		key := []byte(k)
		require.NoError(t, m.DeleteMapEntry(uintptr(unsafe.Pointer(&key[0]))))
	}
}

// countEntries is how the tests see what the programs left in a map: that the
// pending RST was consumed, and that no flow was recorded for it.
func countEntries(t *testing.T, m goebpfmaps.BpfMap) int {
	t.Helper()
	keys, err := m.GetAllMapKeys()
	require.NoError(t, err)
	return len(keys)
}

func TestTCPResetOnDenyKernel(t *testing.T) {
	dir, required := requireBPFKernelTests(t)
	families := []family{
		{"v4", netip.MustParseAddrPort("10.0.0.1:40000"), netip.MustParseAddrPort("10.0.1.2:80"),
			EVENTS_BINARY, TC_EGRESS_BINARY, []string{TC_INGRESS_BINARY, TC_INGRESS_CT_DENY_BINARY}},
		{"v6", netip.MustParseAddrPort("[fd00::1]:40000"), netip.MustParseAddrPort("[fd00:1::2]:80"),
			EVENTS_V6_BINARY, TC_V6_EGRESS_BINARY, []string{TC_V6_INGRESS_BINARY, TC_V6_INGRESS_CT_DENY_BINARY}},
	}
	kfuncsErr := checkKfuncs(ctDenyKfuncs)
	if kfuncsErr != nil && required {
		// nf_conntrack registers the kfuncs when it loads, and the CI runner's
		// kernel has them (both ct-deny variants run there), so in CI their
		// absence means the module isn't loaded, not a kernel without them.
		// Skipping would silently drop half the cases.
		t.Fatalf("kernel lacks the conntrack kfuncs the ct-deny variants need (modprobe nf_conntrack): %v", kfuncsErr)
	}
	for _, fam := range families {
		variants := fam.ingressBinaries
		if kfuncsErr != nil {
			t.Logf("skipping %s: kernel lacks the conntrack kfuncs: %v", variants[1], kfuncsErr)
			variants = variants[:1]
		}
		for _, ingressBinary := range variants {
			t.Run(fam.name+"/"+ingressBinary, func(t *testing.T) {
				progs := loadFamily(t, dir, fam, ingressBinary)
				syn := tcpSegment{src: fam.client, dst: fam.pod, seq: 0x11223344, flags: tcpFlagSyn} // any seq: the RST must ack it + 1

				require.NoError(t, writeTCConfig(progs.config, true))
				var ifindex uint32
				t.Run("flag on: denied SYN answered with RST", func(t *testing.T) {
					ifindex = assertAnsweredWithReset(t, progs, syn)
				})
				t.Run("flag on: SYN on a flow the policy no longer allows answered with RST", func(t *testing.T) {
					// The ingress program has a second deny path: a SYN on a
					// flow it recorded under an earlier policy state, such as a
					// retransmit after a policy change, is evaluated again. A
					// recorded flow whose state differs from the pod's current
					// one takes that path.
					recordStaleFlow(t, progs.conntrack, syn, ifindex)
					assertAnsweredWithReset(t, progs, syn)
				})
				t.Run("a RST that misses its pending entry records no flow with the flag on, as before with it off", func(t *testing.T) {
					// Two SYNs on one tuple, denied before the first RST reaches
					// egress, leave one pending entry for two RSTs. With the
					// pod's egress allowing everything, the second RST is
					// evaluated as the pod's own and allowed. If it recorded a
					// flow, the client's next SYN would match it as a reply and
					// skip ingress policy.
					writePodState(t, progs.egressPodState, POD_STATE_MAP_KEY, DEFAULT_ALLOW)
					defer writePodState(t, progs.egressPodState, POD_STATE_MAP_KEY, DEFAULT_DENY)
					_, first := testRun(t, progs.ingressFD, syn.packet())
					_, second := testRun(t, progs.ingressFD, syn.packet())
					for _, rst := range [][]byte{first, second} {
						verdict, _ := testRun(t, progs.egressFD, rst)
						require.Equal(t, uint32(tcActOK), verdict, "egress passes the RST")
					}
					assert.Zero(t, countEntries(t, progs.conntrack), "no flow recorded for either RST")
					verdict, third := testRun(t, progs.ingressFD, syn.packet())
					assert.Equal(t, uint32(tcActRedirect), verdict, "a third SYN is still denied and answered")
					testRun(t, progs.egressFD, third) // consumes its pending entry, for the cases below

					// With the flag off, a RST the pod sends is recorded as
					// before: only the ingress program's RSTs need the rule.
					require.NoError(t, writeTCConfig(progs.config, false))
					defer func() { require.NoError(t, writeTCConfig(progs.config, true)) }()
					verdict, _ = testRun(t, progs.egressFD, third)
					assert.Equal(t, uint32(tcActOK), verdict, "egress allows the pod's RST")
					assert.Equal(t, 1, countEntries(t, progs.conntrack), "flag off: the RST's flow is recorded as before")
					clearMap(t, progs.conntrack) // the recorded flow would let the cases below in as replies
				})

				for _, tc := range []struct {
					name     string
					flagOn   bool
					flags    uint8
					podState int
					verdict  uint32
				}{
					{"flag off: denied SYN dropped", false, tcpFlagSyn, DEFAULT_DENY, tcActShot},
					// Only a bare SYN is answered. Each segment here fails
					// exactly one of its conditions, so each catches that one
					// being dropped.
					{"flag on: denied segment without SYN dropped", true, 0, DEFAULT_DENY, tcActShot},
					{"flag on: denied SYN-ACK dropped", true, tcpFlagSyn | tcpFlagAck, DEFAULT_DENY, tcActShot},
					{"flag on: denied SYN-FIN dropped", true, tcpFlagSyn | tcpFlagFin, DEFAULT_DENY, tcActShot},
					{"flag on: denied SYN-RST dropped", true, tcpFlagSyn | tcpFlagRst, DEFAULT_DENY, tcActShot},
					// Every other case is denied, so without this one, a RST
					// for every SYN would pass them all. Last: the allowed SYN
					// records a flow, which later packets of the same 5-tuple
					// would match.
					{"flag on: allowed SYN passed unchanged", true, tcpFlagSyn, DEFAULT_ALLOW, tcActOK},
				} {
					t.Run(tc.name, func(t *testing.T) {
						require.NoError(t, writeTCConfig(progs.config, tc.flagOn))
						writePodState(t, progs.ingressPodState, POD_STATE_MAP_KEY, tc.podState)
						segment := syn
						segment.flags = tc.flags
						verdict, out := testRun(t, progs.ingressFD, segment.packet())
						assert.Equal(t, tc.verdict, verdict)
						assert.Equal(t, segment.packet(), out, "packet unchanged")
						assert.Zero(t, countEntries(t, progs.pending), "no RST pending")
					})
				}
			})
		}
	}
}

// staleFlowState is a policy state value no pod state produces, so a flow
// recorded with it always differs from the pod's current state.
const staleFlowState = 0xff

// recordStaleFlow records syn's flow in the conntrack map the way the ingress
// program would have when it allowed it, but with staleFlowState.
func recordStaleFlow(t *testing.T, conntrack goebpfmaps.BpfMap, syn tcpSegment, ifindex uint32) {
	t.Helper()
	value := utils.ConntrackVal{Value: staleFlowState}
	src, dst := syn.src.Addr(), syn.dst.Addr()
	if src.Is4() {
		// The programs store IPv4 addresses as the raw network-order bytes
		// loaded into a native u32, and ports in host order.
		s, d := src.As4(), dst.As4()
		key := utils.ConntrackKey{
			Source_ip: binary.NativeEndian.Uint32(s[:]), Source_port: syn.src.Port(),
			Dest_ip: binary.NativeEndian.Uint32(d[:]), Dest_port: syn.dst.Port(),
			Protocol: ipProtoTCP, Owner_ip: binary.NativeEndian.Uint32(d[:]), Ifindex: ifindex,
		}
		require.NoError(t, conntrack.CreateUpdateMapEntry(uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value)), 0))
		return
	}
	key := utils.ConntrackKeyV6{
		Source_ip: src.As16(), Source_port: syn.src.Port(),
		Dest_ip: dst.As16(), Dest_port: syn.dst.Port(),
		Protocol: ipProtoTCP, Owner_ip: dst.As16(), Ifindex: ifindex,
	}
	require.NoError(t, conntrack.CreateUpdateMapEntry(uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value)), 0))
}
