package events

// import (
// 	"bytes"
// 	"encoding/binary"
// 	"strings"
// 	"testing"
// 	"time"

// 	"github.com/emilyhuaa/aws-network-policy-agent/pkg/utils"
// 	"github.com/go-logr/logr"
// 	"github.com/go-logr/logr/funcr"
// 	"github.com/stretchr/testify/assert"
// )

// type mockLogger struct {
// 	logr.Logger
// 	logs []string
// }

// func (m *mockLogger) Info(msg string, keysAndValues ...interface{}) {
// 	m.logs = append(m.logs, msg)
// }

// func TestCapturePolicyEvents(t *testing.T) {
// 	mockLogger := &mockLogger{Logger: funcr.New(func(prefix, args string) {}, funcr.Options{})}
// 	ringBufferChan := make(chan []byte)

// 	utils.LocalCache = map[string]utils.Metadata{
// 		"192.168.0.1": {Name: "pod1", Namespace: "default"},
// 		"192.168.1.1": {Name: "pod2", Namespace: "kube-system"},
// 	}

// 	t.Run("Valid IPv4 Data", func(t *testing.T) {
// 		data := ringBufferDataV4_t{
// 			SourceIP:   3232235521, //192.168.0.1,
// 			SourcePort: 1234,
// 			DestIP:     3232235777, //192.168.1.1,
// 			DestPort:   80,
// 			Protocol:   6,
// 			Verdict:    1,
// 		}
// 		buf := new(bytes.Buffer)
// 		err := binary.Write(buf, binary.LittleEndian, data)
// 		assert.NoError(t, err)

// 		go CapturePolicyEvents(ringBufferChan, mockLogger.Logger, false, false)
// 		ringBufferChan <- buf.Bytes()

// 		time.Sleep(1 * time.Second)

// 		expectedLog := "Flow Info: Src IP 192.168.0.1 Src Name pod1 Src Namespace default Src Port 1234 Dest IP 192.168.1.1 Dest Name pod2 Dest Namespace kube-system Dest Port 80 Proto TCP Verdict ACCEPT"
// 		logFound := false
// 		for _, log := range mockLogger.logs {
// 			if strings.Contains(log, expectedLog) {
// 				logFound = true
// 				break
// 			}
// 		}
// 		assert.True(t, logFound, "Expected log not found")
// 	})
// }
