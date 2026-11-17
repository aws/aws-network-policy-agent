package ebpf

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	// AWS_EVENTS_DROP_COUNT_MAP is the per-CPU array the datapath increments when
	// bpf_ringbuf_output fails for a DENY event. Key 0 = ingress, key 1 = egress.
	AWS_EVENTS_DROP_COUNT_MAP             = "policy_events_drop_count_map"
	POLICY_EVENTS_DROP_COUNT_MAP_PIN_PATH = "/sys/fs/bpf/globals/aws/maps/global_policy_events_drop_count_map"
	possibleCPUsPath                      = "/sys/devices/system/cpu/possible"

	ringbufDropKeyIngress uint32 = 0
	ringbufDropKeyEgress  uint32 = 1

	// perCPUValueStride is round_up(sizeof(u64), 8): the kernel lays out one
	// 8-byte slot per possible CPU for a PERCPU_ARRAY lookup.
	perCPUValueStride = 8

	// maxPossibleCPUs bounds the slot count so a corrupt cpulist cannot drive a
	// huge allocation. Linux NR_CPUS tops out at 8192.
	maxPossibleCPUs = 1 << 16

	ringbufDropMetricName = "network_policy_event_ringbuf_deny_drops_total"
	ringbufDropMetricHelp = "DENY policy events the datapath failed to write to the policy_events ring buffer (buffer full)"
)

// ringbufDropMetricsOnce makes registration (and its warning on failure)
// happen at most once per process; MustRegister would panic on a duplicate.
var ringbufDropMetricsOnce sync.Once

// parsePossibleCPUs parses the kernel cpulist format ("0-63", "0,2-5", "0")
// and returns maxID+1, the slot count used to size per-CPU lookups. maxID+1 is
// always >= the kernel's num_possible_cpus(), so the buffer is never short.
// Malformed input returns an error; it never panics.
func parsePossibleCPUs(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty cpulist")
	}
	maxID := -1
	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		start, err := parseCPUID(lo)
		if err != nil {
			return 0, fmt.Errorf("invalid cpulist %q: %w", s, err)
		}
		end := start
		if isRange {
			if end, err = parseCPUID(hi); err != nil {
				return 0, fmt.Errorf("invalid cpulist %q: %w", s, err)
			}
			if end < start {
				return 0, fmt.Errorf("invalid cpulist %q: descending range %q", s, part)
			}
		}
		if end > maxID {
			maxID = end
		}
	}
	return maxID + 1, nil
}

// parseCPUID accepts only plain decimal digits (no sign, no spaces) below
// maxPossibleCPUs.
func parseCPUID(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty cpu id")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid cpu id %q", s)
		}
	}
	id, err := strconv.ParseUint(s, 10, 32)
	if err != nil || id >= maxPossibleCPUs {
		return 0, fmt.Errorf("cpu id %q out of range", s)
	}
	return int(id), nil
}

// sumPerCPU sums nCPU little-endian u64 slots (stride 8 = round_up(8, 8)).
// Slots beyond len(buf) are ignored, so a short buffer never panics. The sum
// wraps mod 2^64.
func sumPerCPU(buf []byte, nCPU int) uint64 {
	var sum uint64
	for i := 0; i < nCPU; i++ {
		off := i * perCPUValueStride
		if off+perCPUValueStride > len(buf) {
			break
		}
		sum += binary.LittleEndian.Uint64(buf[off : off+perCPUValueStride])
	}
	return sum
}

// mapEntryGetter is the one BpfMap method the reader needs; *goebpfmaps.BpfMap
// satisfies it (GetMapEntry has a pointer receiver). It lets tests fake the map.
type mapEntryGetter interface {
	GetMapEntry(key, value uintptr) error
}

// ringbufDropReader exports the Ringbuf_Drop_Counter as a per-process
// counter: raw map value minus the snapshot taken at registration, never
// decreasing.
type ringbufDropReader struct {
	m        mapEntryGetter
	nCPU     int
	mu       sync.Mutex
	baseline [2]uint64 // snapshot at registration
	last     [2]uint64 // last exported value (monotonic guard)
}

// readRaw returns the sum across CPUs of the map entry for key.
func (r *ringbufDropReader) readRaw(key uint32) (uint64, error) {
	buf := make([]byte, perCPUValueStride*r.nCPU)
	if err := r.m.GetMapEntry(uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&buf[0]))); err != nil {
		return 0, err
	}
	return sumPerCPU(buf, r.nCPU), nil
}

// value returns the drops for key since registration. On a read error it
// increments sdkAPIErr{fn="ReadRingbufDropCounter"} and returns the last value.
func (r *ringbufDropReader) value(key uint32) float64 {
	if key > ringbufDropKeyEgress {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	raw, err := r.readRaw(key)
	if err != nil {
		sdkAPIErr.WithLabelValues("ReadRingbufDropCounter").Inc()
		return float64(r.last[key])
	}
	// raw < baseline only if the pinned map was replaced underneath us; keep
	// the exported value where it was rather than going backwards.
	if raw >= r.baseline[key] {
		if v := raw - r.baseline[key]; v > r.last[key] {
			r.last[key] = v
		}
	}
	return float64(r.last[key])
}

// newRingbufDropReader sizes per-CPU reads from the possible-CPU cpulist and
// snapshots the current raw values as the baseline.
func newRingbufDropReader(m mapEntryGetter, cpulist string) (*ringbufDropReader, error) {
	nCPU, err := parsePossibleCPUs(cpulist)
	if err != nil {
		return nil, err
	}
	r := &ringbufDropReader{m: m, nCPU: nCPU}
	for _, key := range []uint32{ringbufDropKeyIngress, ringbufDropKeyEgress} {
		raw, err := r.readRaw(key)
		if err != nil {
			return nil, fmt.Errorf("read baseline for key %d: %w", key, err)
		}
		r.baseline[key] = raw
	}
	return r, nil
}

// registerRingbufDropMetrics registers network_policy_event_ringbuf_deny_drops_total
// (direction=ingress|egress) on the controller-runtime registry. The map is
// read only on scrape. If the possible-CPU file cannot be read or parsed, or
// the baseline read fails, it warns once and skips registration; startup
// continues. Subsequent calls are no-ops.
func registerRingbufDropMetrics(m goebpfmaps.BpfMap) {
	ringbufDropMetricsOnce.Do(func() {
		data, err := os.ReadFile(possibleCPUsPath)
		if err != nil {
			log().Warnf("Ring buffer DENY drop metric disabled: cannot read %s: %v", possibleCPUsPath, err)
			return
		}
		// m is this call's copy; the reader keeps a pointer to it.
		r, err := newRingbufDropReader(&m, string(data))
		if err != nil {
			log().Warnf("Ring buffer DENY drop metric disabled: %v", err)
			return
		}
		for _, d := range []struct {
			label string
			key   uint32
		}{{"ingress", ringbufDropKeyIngress}, {"egress", ringbufDropKeyEgress}} {
			key := d.key
			metrics.Registry.MustRegister(prometheus.NewCounterFunc(
				prometheus.CounterOpts{
					Name:        ringbufDropMetricName,
					Help:        ringbufDropMetricHelp,
					ConstLabels: prometheus.Labels{"direction": d.label},
				},
				func() float64 { return r.value(key) },
			))
		}
	})
}
