package ebpf

import (
	"encoding/binary"
	"errors"
	"math/big"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDropMap fakes the per-CPU drop-count map: GetMapEntry writes perCPU[key]
// as little-endian u64 slots into the caller's buffer, or returns err.
type fakeDropMap struct {
	perCPU map[uint32][]uint64
	err    error
}

func (f *fakeDropMap) GetMapEntry(key, value uintptr) error {
	if f.err != nil {
		return f.err
	}
	// The caller keeps both pointees alive across the call (as the SDK does);
	// reinterpreting the uintptr's storage avoids vet's unsafeptr check.
	k := **(**uint32)(unsafe.Pointer(&key))
	vals := f.perCPU[k]
	buf := unsafe.Slice(*(**byte)(unsafe.Pointer(&value)), len(vals)*perCPUValueStride)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(buf[i*perCPUValueStride:], v)
	}
	return nil
}

func readErrCount() float64 {
	return testutil.ToFloat64(sdkAPIErr.WithLabelValues("ReadRingbufDropCounter"))
}

func TestRingbufDropReader_ValueIsRawMinusBaseline(t *testing.T) {
	f := &fakeDropMap{perCPU: map[uint32][]uint64{
		ringbufDropKeyIngress: {3, 4},
		ringbufDropKeyEgress:  {10, 0},
	}}
	r, err := newRingbufDropReader(f, "0-1\n")
	require.NoError(t, err)

	assert.Equal(t, 0.0, r.value(ringbufDropKeyIngress))
	assert.Equal(t, 0.0, r.value(ringbufDropKeyEgress))

	f.perCPU[ringbufDropKeyIngress] = []uint64{5, 7} // raw 12, baseline 7
	f.perCPU[ringbufDropKeyEgress] = []uint64{10, 5} // raw 15, baseline 10
	assert.Equal(t, 5.0, r.value(ringbufDropKeyIngress))
	assert.Equal(t, 5.0, r.value(ringbufDropKeyEgress))

	// Out-of-range key exports nothing.
	assert.Equal(t, 0.0, r.value(2))
}

func TestRingbufDropReader_BaselineReadError(t *testing.T) {
	_, err := newRingbufDropReader(&fakeDropMap{err: errors.New("boom")}, "0")
	assert.Error(t, err)
}

func TestRingbufDropReader_ReadErrorReturnsLastAndCounts(t *testing.T) {
	f := &fakeDropMap{perCPU: map[uint32][]uint64{
		ringbufDropKeyIngress: {1},
		ringbufDropKeyEgress:  {0},
	}}
	r, err := newRingbufDropReader(f, "0")
	require.NoError(t, err)

	f.perCPU[ringbufDropKeyIngress] = []uint64{4}
	assert.Equal(t, 3.0, r.value(ringbufDropKeyIngress))

	before := readErrCount()
	f.err = errors.New("read failed")
	assert.Equal(t, 3.0, r.value(ringbufDropKeyIngress))
	assert.Equal(t, 0.0, r.value(ringbufDropKeyEgress))
	assert.Equal(t, before+2, readErrCount())

	// Recovery resumes from the map.
	f.err = nil
	f.perCPU[ringbufDropKeyIngress] = []uint64{6}
	assert.Equal(t, 5.0, r.value(ringbufDropKeyIngress))
	assert.Equal(t, before+2, readErrCount())
}

func TestRingbufDropReader_NeverDecreases(t *testing.T) {
	f := &fakeDropMap{perCPU: map[uint32][]uint64{
		ringbufDropKeyIngress: {50, 50}, // baseline 100
		ringbufDropKeyEgress:  {0, 0},
	}}
	r, err := newRingbufDropReader(f, "0,1")
	require.NoError(t, err)

	steps := []struct {
		raw  uint64
		want float64
	}{
		{110, 10},
		{105, 10}, // raw dropped but still above baseline
		{40, 10},  // raw below baseline (map replaced)
		{0, 10},
		{130, 30}, // grows again
		{130, 30},
	}
	for i, s := range steps {
		f.perCPU[ringbufDropKeyIngress] = []uint64{s.raw, 0}
		assert.Equal(t, s.want, r.value(ringbufDropKeyIngress), "step %d raw=%d", i, s.raw)
	}
}

func TestParsePossibleCPUs_Examples(t *testing.T) {
	ok := map[string]int{
		"0":         1,
		"0-63":      64,
		"0-63\n":    64,
		"0,2-5":     6,
		"3,0-1":     4,
		"0-3,8-11":  12,
		" 0-1,7 \n": 8,
	}
	for in, want := range ok {
		got, err := parsePossibleCPUs(in)
		assert.NoError(t, err, "input %q", in)
		assert.Equal(t, want, got, "input %q", in)
	}

	bad := []string{"", "\n", "-", "0-", "-3", "a", "0,,1", "5-2", "0-1-2", "+1", "1 - 2", "0,", "99999999999", "65536"}
	for _, in := range bad {
		assert.NotPanics(t, func() {
			_, err := parsePossibleCPUs(in)
			assert.Error(t, err, "input %q", in)
		})
	}
}

func TestSumPerCPU_Examples(t *testing.T) {
	buf := make([]byte, 8*3)
	binary.LittleEndian.PutUint64(buf[0:], 1)
	binary.LittleEndian.PutUint64(buf[8:], 2)
	binary.LittleEndian.PutUint64(buf[16:], 40)
	assert.Equal(t, uint64(43), sumPerCPU(buf, 3))
	assert.Equal(t, uint64(3), sumPerCPU(buf, 2))
	// Short buffer: extra slots are ignored, no panic.
	assert.Equal(t, uint64(43), sumPerCPU(buf, 10))
	// Wraps mod 2^64.
	binary.LittleEndian.PutUint64(buf[0:], ^uint64(0))
	binary.LittleEndian.PutUint64(buf[8:], 2)
	assert.Equal(t, uint64(1), sumPerCPU(buf[:16], 2))
}

// renderCPUList renders a sorted, de-duplicated, non-empty set of CPU ids in
// kernel cpulist syntax. Consecutive runs are randomly split into sub-ranges,
// singletons are sometimes written as "a-a", some parts are duplicated, and
// the parts are shuffled, so every merge/order variant parsePossibleCPUs may
// see is exercised. It returns the parts (unjoined) so callers can mutate them.
func renderCPUList(rng *rand.Rand, ids []int) []string {
	var parts []string
	emit := func(lo, hi int) {
		if lo == hi && rng.Intn(4) != 0 {
			parts = append(parts, strconv.Itoa(lo))
		} else {
			parts = append(parts, strconv.Itoa(lo)+"-"+strconv.Itoa(hi))
		}
	}
	for i := 0; i < len(ids); {
		j := i
		for j+1 < len(ids) && ids[j+1] == ids[j]+1 {
			j++
		}
		// Split run ids[i..j] into random sub-ranges.
		lo := ids[i]
		for lo <= ids[j] {
			hi := lo + rng.Intn(ids[j]-lo+1)
			emit(lo, hi)
			lo = hi + 1
		}
		i = j + 1
	}
	// Occasionally repeat an existing part (overlap is legal in a cpulist).
	if rng.Intn(4) == 0 {
		parts = append(parts, parts[rng.Intn(len(parts))])
	}
	rng.Shuffle(len(parts), func(a, b int) { parts[a], parts[b] = parts[b], parts[a] })
	return parts
}

// randomCPUSet returns a sorted, de-duplicated, non-empty set of CPU ids below
// maxPossibleCPUs, mixing scattered ids with a contiguous block.
func randomCPUSet(rng *rand.Rand) []int {
	limit := 8192
	if rng.Intn(10) == 0 {
		limit = maxPossibleCPUs
	}
	set := map[int]struct{}{}
	for k := 1 + rng.Intn(32); k > 0; k-- {
		set[rng.Intn(limit)] = struct{}{}
	}
	if rng.Intn(2) == 0 {
		start := rng.Intn(limit)
		end := start + 1 + rng.Intn(128)
		for id := start; id < limit && id < end; id++ {
			set[id] = struct{}{}
		}
	}
	ids := make([]int, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

// Feature: policy-event-logging-efficiency, Property 10: Per-CPU drop counter
// read is sized and summed correctly. For any non-empty CPU-id set rendered as
// a cpulist, parsePossibleCPUs returns max(id)+1 (>= number of ids).
// **Validates: Requirements 15.3, 15.4**
func TestProperty_ParsePossibleCPUs_Valid(t *testing.T) {
	rng := rand.New(rand.NewSource(10))
	ws := []string{"", "", "\n", " ", " \n", "\t"}
	for i := 0; i < 500; i++ {
		ids := randomCPUSet(rng)
		in := ws[rng.Intn(len(ws))] + strings.Join(renderCPUList(rng, ids), ",") + ws[rng.Intn(len(ws))]
		got, err := parsePossibleCPUs(in)
		if !assert.NoError(t, err, "input %q", in) {
			continue
		}
		assert.Equal(t, ids[len(ids)-1]+1, got, "input %q", in)
		assert.GreaterOrEqual(t, got, len(ids), "input %q", in)
	}
}

// Feature: policy-event-logging-efficiency, Property 10: Per-CPU drop counter
// read is sized and summed correctly. Malformed cpulist strings return an
// error and never panic.
// **Validates: Requirements 15.3, 15.4**
func TestProperty_ParsePossibleCPUs_Malformed(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	// Each generator yields a part that is invalid wherever it is placed in
	// the list (no leading/trailing whitespace, which TrimSpace would strip).
	badParts := []func() string{
		func() string { return "" }, // empty part: ",,", leading or trailing ","
		func() string { return strconv.Itoa(rng.Intn(64)) + "a" },
		func() string { return "x" },
		func() string { return "0x" + strconv.Itoa(rng.Intn(16)) },
		func() string { // descending range
			lo := rng.Intn(1000)
			return strconv.Itoa(lo+1+rng.Intn(1000)) + "-" + strconv.Itoa(lo)
		},
		func() string { return strconv.Itoa(maxPossibleCPUs + rng.Intn(1<<20)) },
		func() string { return "99999999999999999999999" },
		func() string { return "+" + strconv.Itoa(rng.Intn(64)) },
		func() string { return "-" + strconv.Itoa(rng.Intn(64)) },
		func() string { return strconv.Itoa(rng.Intn(64)) + "-" },
		func() string { return "-" },
		func() string { return "1-2-3" },
		func() string { return "1 -2" },
		func() string { return "1 2" },
		func() string { return "1\t2" },
	}
	for i := 0; i < 500; i++ {
		var in string
		if rng.Intn(20) == 0 {
			in = []string{"", " ", "\n", "\t\n"}[rng.Intn(4)] // whitespace only
		} else {
			parts := renderCPUList(rng, randomCPUSet(rng))
			pos := rng.Intn(len(parts) + 1)
			bad := badParts[rng.Intn(len(badParts))]()
			parts = append(parts[:pos], append([]string{bad}, parts[pos:]...)...)
			in = strings.Join(parts, ",")
		}
		assert.NotPanics(t, func() {
			_, err := parsePossibleCPUs(in)
			assert.Error(t, err, "input %q", in)
		}, "input %q", in)
	}

	// Arbitrary strings: never panic; any accepted input yields a sane count.
	const alphabet = "0123456789--,, \n\tab+x"
	for i := 0; i < 1000; i++ {
		b := make([]byte, rng.Intn(24))
		for k := range b {
			b[k] = alphabet[rng.Intn(len(alphabet))]
		}
		in := string(b)
		assert.NotPanics(t, func() {
			n, err := parsePossibleCPUs(in)
			if err == nil {
				assert.True(t, n >= 1 && n <= maxPossibleCPUs, "input %q -> %d", in, n)
			}
		}, "input %q", in)
	}
}

// Feature: policy-event-logging-efficiency, Property 10: Per-CPU drop counter
// read is sized and summed correctly. For any n u64 values encoded
// little-endian, sumPerCPU(buf, n) equals their sum mod 2^64; bytes past the
// n slots are ignored.
// **Validates: Requirements 15.3, 15.4**
func TestProperty_SumPerCPU(t *testing.T) {
	rng := rand.New(rand.NewSource(12))
	for i := 0; i < 500; i++ {
		n := rng.Intn(300)
		buf := make([]byte, n*perCPUValueStride+rng.Intn(3)*perCPUValueStride)
		rng.Read(buf) // trailing slots hold garbage that must not be summed
		// Expected sum computed with arbitrary precision, then reduced mod
		// 2^64, independent of sumPerCPU's native wrapping.
		want := new(big.Int)
		for k := 0; k < n; k++ {
			var v uint64
			switch rng.Intn(4) {
			case 0:
				v = ^uint64(0) - uint64(rng.Intn(16)) // near max: forces wrap
			case 1:
				v = uint64(rng.Intn(1000))
			default:
				v = rng.Uint64()
			}
			binary.LittleEndian.PutUint64(buf[k*perCPUValueStride:], v)
			want.Add(want, new(big.Int).SetUint64(v))
		}
		want.Mod(want, new(big.Int).Lsh(big.NewInt(1), 64))
		assert.Equal(t, want.Uint64(), sumPerCPU(buf, n), "n=%d", n)
	}
}
