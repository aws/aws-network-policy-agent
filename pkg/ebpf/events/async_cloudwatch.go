package events

import (
	"context"
	"sync"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/aws/services"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

const (
	// Batching configuration
	DefaultBatchSize     = 100             // Max events per batch
	DefaultBatchTimeout  = 5 * time.Second // Max time to wait before sending batch
	DefaultChannelBuffer = 1000            // Buffered channel size to prevent blocking

	// CloudWatch Logs limits
	MaxLogEventsPerBatch = 10000   // AWS limit
	MaxBatchSizeBytes    = 1048576 // 1MB AWS limit
)

// CloudWatchLogEvent represents a log event to be sent to CloudWatch
type CloudWatchLogEvent struct {
	Message   string
	Timestamp time.Time
}

// AsyncCloudWatchUploader handles asynchronous CloudWatch log uploads with batching
type AsyncCloudWatchUploader struct {
	// Configuration
	batchSize    int
	batchTimeout time.Duration

	// CloudWatch client and stream info
	cwl           services.CloudWatchLogs
	logGroupName  string
	logStreamName string
	sequenceToken string

	// Channel for receiving log events
	eventChan chan CloudWatchLogEvent

	// Context and synchronization
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Sequence token protection
	tokenMutex sync.Mutex
}

// AsyncCloudWatchConfig contains configuration for the async uploader
type AsyncCloudWatchConfig struct {
	BatchSize     int
	BatchTimeout  time.Duration
	ChannelBuffer int
	LogGroupName  string
	LogStreamName string
	CWLClient     services.CloudWatchLogs
}

var (
	// Global async uploader instance
	globalAsyncUploader *AsyncCloudWatchUploader
	uploaderMutex       sync.RWMutex
)

// NewAsyncCloudWatchUploader creates a new async CloudWatch uploader
func NewAsyncCloudWatchUploader(config AsyncCloudWatchConfig) *AsyncCloudWatchUploader {
	if config.BatchSize <= 0 {
		config.BatchSize = DefaultBatchSize
	}
	if config.BatchTimeout <= 0 {
		config.BatchTimeout = DefaultBatchTimeout
	}
	if config.ChannelBuffer <= 0 {
		config.ChannelBuffer = DefaultChannelBuffer
	}

	return &AsyncCloudWatchUploader{
		batchSize:     config.BatchSize,
		batchTimeout:  config.BatchTimeout,
		cwl:           config.CWLClient,
		logGroupName:  config.LogGroupName,
		logStreamName: config.LogStreamName,
		eventChan:     make(chan CloudWatchLogEvent, config.ChannelBuffer),
	}
}

// Start begins the async upload process
func (u *AsyncCloudWatchUploader) Start(ctx context.Context) error {
	u.ctx, u.cancel = context.WithCancel(ctx)

	u.wg.Add(1)
	go u.uploadWorker()

	logger.Get().Infof("Async CloudWatch uploader started with batchSize=%d, batchTimeout=%v, channelBuffer=%d",
		u.batchSize, u.batchTimeout, cap(u.eventChan))

	return nil
}

// Stop gracefully shuts down the uploader
func (u *AsyncCloudWatchUploader) Stop() {
	if u.cancel != nil {
		u.cancel()
	}
	u.wg.Wait()

	// Drain remaining events
	close(u.eventChan)
	remainingEvents := len(u.eventChan)
	if remainingEvents > 0 {
		logger.Get().Warnf("Dropping %d remaining events during shutdown", remainingEvents)
	}

	logger.Get().Info("Async CloudWatch uploader stopped")
}

// SendEvent sends a log event asynchronously (non-blocking)
func (u *AsyncCloudWatchUploader) SendEvent(message string) {
	event := CloudWatchLogEvent{
		Message:   message,
		Timestamp: time.Now(),
	}

	select {
	case u.eventChan <- event:
		// Event queued successfully
	default:
		// Channel is full, drop the event
		logger.Get().Warn("CloudWatch event channel full, dropping event")
	}
}

// uploadWorker is the background goroutine that batches and uploads events
func (u *AsyncCloudWatchUploader) uploadWorker() {
	defer u.wg.Done()

	ticker := time.NewTicker(u.batchTimeout)
	defer ticker.Stop()

	batch := make([]CloudWatchLogEvent, 0, u.batchSize)

	for {
		select {
		case <-u.ctx.Done():
			// Upload remaining batch before shutdown
			if len(batch) > 0 {
				u.uploadBatch(batch)
			}
			return

		case event := <-u.eventChan:
			batch = append(batch, event)

			// Upload when batch is full
			if len(batch) >= u.batchSize {
				u.uploadBatch(batch)
				batch = batch[:0]            // Reset slice but keep capacity
				ticker.Reset(u.batchTimeout) // Reset timer
			}

		case <-ticker.C:
			// Upload batch on timeout (even if not full)
			if len(batch) > 0 {
				u.uploadBatch(batch)
				batch = batch[:0] // Reset slice but keep capacity
			}
		}
	}
}

// uploadBatch uploads a batch of events to CloudWatch
func (u *AsyncCloudWatchUploader) uploadBatch(events []CloudWatchLogEvent) {
	if len(events) == 0 {
		return
	}

	// Convert to CloudWatch log events
	logEvents := make([]types.InputLogEvent, len(events))
	for i, event := range events {
		logEvents[i] = types.InputLogEvent{
			Message:   aws.String(event.Message),
			Timestamp: aws.Int64(event.Timestamp.UnixNano() / int64(time.Millisecond)),
		}
	}

	// Prepare upload request
	u.tokenMutex.Lock()
	input := &cloudwatchlogs.PutLogEventsInput{
		LogEvents:     logEvents,
		LogGroupName:  aws.String(u.logGroupName),
		LogStreamName: aws.String(u.logStreamName),
	}

	if u.sequenceToken != "" {
		input.SequenceToken = aws.String(u.sequenceToken)
	}
	u.tokenMutex.Unlock()

	// Upload to CloudWatch
	resp, err := u.cwl.PutLogEvents(u.ctx, input)
	if err != nil {
		logger.Get().Errorf("Failed to upload batch of %d events to CloudWatch: %v", len(events), err)
		return
	}

	// Update sequence token for next upload
	u.tokenMutex.Lock()
	if resp != nil && resp.NextSequenceToken != nil {
		u.sequenceToken = *resp.NextSequenceToken
	}
	u.tokenMutex.Unlock()

	logger.Get().Debugf("Successfully uploaded batch of %d events to CloudWatch", len(events))
}

// Global functions for managing the async uploader

// InitializeAsyncCloudWatchUploader initializes the global async uploader
func InitializeAsyncCloudWatchUploader(ctx context.Context, config AsyncCloudWatchConfig) error {
	uploaderMutex.Lock()
	defer uploaderMutex.Unlock()

	if globalAsyncUploader != nil {
		logger.Get().Warn("Async CloudWatch uploader already initialized")
		return nil
	}

	globalAsyncUploader = NewAsyncCloudWatchUploader(config)
	return globalAsyncUploader.Start(ctx)
}

// ShutdownAsyncCloudWatchUploader shuts down the global async uploader
func ShutdownAsyncCloudWatchUploader() {
	uploaderMutex.Lock()
	defer uploaderMutex.Unlock()

	if globalAsyncUploader != nil {
		globalAsyncUploader.Stop()
		globalAsyncUploader = nil
	}
}

// SendAsyncCloudWatchEvent sends an event to the global async uploader
func SendAsyncCloudWatchEvent(message string) {
	uploaderMutex.RLock()
	defer uploaderMutex.RUnlock()

	if globalAsyncUploader != nil {
		globalAsyncUploader.SendEvent(message)
	}
}
