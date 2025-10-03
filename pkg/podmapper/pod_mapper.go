package podmapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/ipamd/datastore"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/fsnotify/fsnotify"
)

const (
	// DefaultIPAMPath is the default path to the IPAM checkpoint file
	DefaultIPAMPath = "/var/run/aws-node/ipam.json"
	// UnknownPod is returned when pod name cannot be determined
	UnknownPod = ""
)

func log() logger.Logger {
	return logger.Get()
}

// PodMapper provides IP to pod name mapping functionality with file watching
type PodMapper interface {
	// GetPodName returns the pod name for a given IP address
	// Returns namespace/podname format or empty string if not found
	GetPodName(ip string) string

	// Start begins the file watcher and initial load
	Start(ctx context.Context) error

	// Stop stops the file watcher
	Stop()

	// GetMappingStats returns statistics about current mappings
	GetMappingStats() (totalMappings int, ipv4Count int)
}

// podMapper implements the PodMapper interface with file watching
type podMapper struct {
	// ipamPath is the path to the IPAM checkpoint file
	ipamPath string

	// ipToPodMap maps IP addresses to pod names in "namespace/podname" format
	// Using sync.Map for thread-safe concurrent access
	ipToPodMap sync.Map

	// File watcher
	watcher *fsnotify.Watcher

	// ctx and cancel for managing goroutines
	ctx    context.Context
	cancel context.CancelFunc

	// wg for graceful shutdown
	wg sync.WaitGroup

	// lastModTime tracks file modification time to avoid duplicate processing
	lastModTime time.Time
	modTimeMux  sync.RWMutex
}

// PodMapperConfig contains configuration for the pod mapper
type PodMapperConfig struct {
	IPAMPath string
}

// NewPodMapper creates a new pod mapper instance with file watching
func NewPodMapper(config PodMapperConfig) PodMapper {
	if config.IPAMPath == "" {
		config.IPAMPath = DefaultIPAMPath
	}

	return &podMapper{
		ipamPath: config.IPAMPath,
	}
}

// Start begins the file watcher and performs initial load
func (p *podMapper) Start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)

	// Create file watcher
	var err error
	p.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Perform initial load
	if err := p.loadIPAMData(); err != nil {
		log().Warnf("Initial IPAM data load failed: %v", err)
	}

	// Watch the IPAM file and its parent directory
	// We watch the directory because the file might be recreated
	ipamDir := filepath.Dir(p.ipamPath)
	if err := p.watcher.Add(ipamDir); err != nil {
		p.watcher.Close()
		return fmt.Errorf("failed to watch directory %s: %w", ipamDir, err)
	}

	// Start file watcher goroutine
	p.wg.Add(1)
	go p.watcherLoop()

	log().Infof("Pod mapper started, watching IPAM file: %s", p.ipamPath)
	return nil
}

// Stop stops the file watcher and cleans up
func (p *podMapper) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	if p.watcher != nil {
		p.watcher.Close()
	}
	p.wg.Wait()
	log().Info("Pod mapper stopped")
}

// GetPodName returns the pod name for a given IP address
func (p *podMapper) GetPodName(ip string) string {
	if value, ok := p.ipToPodMap.Load(ip); ok {
		return value.(string)
	}
	return UnknownPod
}

// GetMappingStats returns statistics about the current mapping
func (p *podMapper) GetMappingStats() (int, int) {
	totalMappings := 0
	ipv4Count := 0

	p.ipToPodMap.Range(func(key, value interface{}) bool {
		totalMappings++
		// Simple heuristic: if it contains ":", it's likely IPv6
		if ip := key.(string); !containsColon(ip) {
			ipv4Count++
		}
		return true
	})

	return totalMappings, ipv4Count
}

// watcherLoop handles file system events
func (p *podMapper) watcherLoop() {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return

		case event, ok := <-p.watcher.Events:
			if !ok {
				return
			}

			// Only process events for our target file
			if event.Name != p.ipamPath {
				continue
			}

			// Handle file events (write, create, rename)
			if event.Op&fsnotify.Write == fsnotify.Write ||
				event.Op&fsnotify.Create == fsnotify.Create ||
				event.Op&fsnotify.Rename == fsnotify.Rename {

				// Check if file was actually modified to avoid duplicate processing
				if p.shouldProcessFile() {
					log().Debugf("IPAM file changed, reloading: %s", event.Name)
					if err := p.loadIPAMData(); err != nil {
						log().Errorf("Failed to reload IPAM data after file change: %v", err)
					}
				}
			}

		case err, ok := <-p.watcher.Errors:
			if !ok {
				return
			}
			log().Errorf("File watcher error: %v", err)
		}
	}
}

// shouldProcessFile checks if the file should be processed based on modification time
func (p *podMapper) shouldProcessFile() bool {
	stat, err := os.Stat(p.ipamPath)
	if err != nil {
		log().Debugf("Cannot stat IPAM file: %v", err)
		return true // Process anyway if we can't check
	}

	p.modTimeMux.Lock()
	defer p.modTimeMux.Unlock()

	modTime := stat.ModTime()
	if modTime.After(p.lastModTime) {
		p.lastModTime = modTime
		return true
	}
	return false
}

// loadIPAMData reads and parses the IPAM checkpoint file
func (p *podMapper) loadIPAMData() error {
	start := time.Now()

	// Read and parse the IPAM file
	checkpointData, err := p.readIPAMFile()
	if err != nil {
		return fmt.Errorf("failed to read IPAM file: %w", err)
	}

	// Build new mapping
	newMapping := make(map[string]string)
	validAllocations := 0

	for _, allocation := range checkpointData.Allocations {
		// Skip entries without pod information
		if allocation.Metadata.K8SPodName == "" || allocation.Metadata.K8SPodNamespace == "" {
			continue
		}

		podName := fmt.Sprintf("%s/%s", allocation.Metadata.K8SPodNamespace, allocation.Metadata.K8SPodName)

		// Handle both IPv4 and IPv6
		if allocation.IPv4 != "" {
			newMapping[allocation.IPv4] = podName
			validAllocations++
		}
		if allocation.IPv6 != "" {
			newMapping[allocation.IPv6] = podName
			validAllocations++
		}
	}

	// Update the concurrent map atomically
	// First, clear old entries
	p.ipToPodMap.Range(func(key, value interface{}) bool {
		p.ipToPodMap.Delete(key)
		return true
	})

	// Add new entries
	for ip, podName := range newMapping {
		p.ipToPodMap.Store(ip, podName)
	}

	duration := time.Since(start)
	log().Debugf("Pod mapping loaded: %d valid allocations processed in %v", validAllocations, duration)

	return nil
}

// readIPAMFile reads and parses the IPAM checkpoint file
func (p *podMapper) readIPAMFile() (*datastore.CheckpointData, error) {
	data, err := os.ReadFile(p.ipamPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", p.ipamPath, err)
	}

	var checkpointData datastore.CheckpointData
	if err := json.Unmarshal(data, &checkpointData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &checkpointData, nil
}

// containsColon is a helper function to distinguish IPv4 from IPv6
func containsColon(s string) bool {
	for _, c := range s {
		if c == ':' {
			return true
		}
	}
	return false
}

// Global pod mapper instance
var (
	globalPodMapper PodMapper
	mapperMutex     sync.RWMutex
)

// InitializePodMapper initializes the global pod mapper
func InitializePodMapper(ctx context.Context, config PodMapperConfig) error {
	mapperMutex.Lock()
	defer mapperMutex.Unlock()

	if globalPodMapper != nil {
		log().Warn("Pod mapper already initialized")
		return nil
	}

	globalPodMapper = NewPodMapper(config)
	return globalPodMapper.Start(ctx)
}

// ShutdownPodMapper shuts down the global pod mapper
func ShutdownPodMapper() {
	mapperMutex.Lock()
	defer mapperMutex.Unlock()

	if globalPodMapper != nil {
		globalPodMapper.Stop()
		globalPodMapper = nil
	}
}

// GetPodNameForIP gets the pod name for an IP using the global mapper
func GetPodNameForIP(ip string) string {
	mapperMutex.RLock()
	defer mapperMutex.RUnlock()

	if globalPodMapper != nil {
		return globalPodMapper.GetPodName(ip)
	}
	return UnknownPod
}

// GetGlobalMappingStats returns statistics from the global mapper
func GetGlobalMappingStats() (int, int) {
	mapperMutex.RLock()
	defer mapperMutex.RUnlock()

	if globalPodMapper != nil {
		return globalPodMapper.GetMappingStats()
	}
	return 0, 0
}
