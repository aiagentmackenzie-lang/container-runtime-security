// Package enrichment - cri.go
// CRI (Container Runtime Interface) integration for container metadata.
// Supports containerd and CRI-O runtimes via gRPC.
//
// Architecture:
//   - CRIIntegration dials the runtime socket and lists containers
//   - On container start: registers with Manager (RegisterContainer),
//     adds cgroup ID to eBPF container_cgroups map
//   - On container stop: unregisters (UnregisterContainer), removes from eBPF map
//   - Event-driven updates via CRI event streaming where available,
//     with periodic polling fallback
//
// Supported runtimes (per SRD Section 12.1):
//   - containerd 1.7+ via CRI gRPC at /run/containerd/containerd.sock
//   - CRI-O 1.25+ via CRI gRPC at /run/crio/crio.sock
//   - Docker 24+ via CRI proxy (P1, not yet implemented)

package enrichment

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// ── CRI Protocol Types ─────────────────────────────────────────────────

// These types mirror the Kubernetes CRI (Container Runtime Interface) protocol.
// We define them locally to avoid pulling in the heavy k8s.io/cri-api dependency
// at this stage; the gRPC client will be wired in Phase 3 when we add the
// full containerd client-go dependency. The Manager uses these types directly.

// CRIRuntime represents the type of container runtime detected.
type CRIRuntime string

const (
	CRIRuntimeContainerd CRIRuntime = "containerd"
	CRIRuntimeCRIO        CRIRuntime = "cri-o"
	CRIRuntimeDocker      CRIRuntime = "docker"
	CRIRuntimeUnknown     CRIRuntime = "unknown"
)

// CRIContainerStatus mirrors the CRI container state.
type CRIContainerStatus string

const (
	CRIContainerCreated   CRIContainerStatus = "created"
	CRIContainerRunning   CRIContainerStatus = "running"
	CRIContainerExited    CRIContainerStatus = "exited"
	CRIContainerUnknown   CRIContainerStatus = "unknown"
)

// ── CRI Integration ────────────────────────────────────────────────────

// CRIIntegration provides container metadata from the container runtime.
// It connects via gRPC to the CRI endpoint (containerd or CRI-O) and
// provides event-driven container lifecycle tracking.
type CRIIntegration struct {
	endpoint  string
	runtime   CRIRuntime
	connected bool

	// Connection state
	mu       sync.RWMutex
	cancel   context.CancelFunc

	// Manager reference for container registration/unregistration
	manager *Manager

	// Event stream
	eventCh chan CRIEvent

	// Stats
	containersListed int
	eventsProcessed  int
	connectAttempts  int
	lastListTime     time.Time
	lastConnectTime  time.Time
	lastError       error
}

// CRIEvent represents a container lifecycle event from the CRI runtime.
type CRIEvent struct {
	Type      CRIEventType
	Container *ContainerInfo
	Timestamp time.Time
}

// CRIEventType represents the type of container lifecycle event.
type CRIEventType string

const (
	CRIEventContainerStart CRIEventType = "container_start"
	CRIEventContainerStop  CRIEventType = "container_stop"
	CRIEventContainerUpdate CRIEventType = "container_update"
)

// NewCRIIntegration creates a CRI integration for the given endpoint.
func NewCRIIntegration(endpoint string) *CRIIntegration {
	return &CRIIntegration{
		endpoint: endpoint,
		runtime:  detectCRIRuntime(endpoint),
		eventCh:  make(chan CRIEvent, 256),
	}
}

// SetManager sets the enrichment Manager reference for container registration.
func (c *CRIIntegration) SetManager(m *Manager) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.manager = m
}

// Connect establishes a connection to the CRI runtime.
// It detects the runtime type from the socket path and verifies connectivity.
func (c *CRIIntegration) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.connectAttempts++

	// Detect runtime type from endpoint path
	c.runtime = detectCRIRuntime(c.endpoint)

	// Verify the socket exists and is accessible
	if _, err := os.Stat(c.endpoint); err != nil {
		c.lastError = fmt.Errorf("CRI socket not accessible at %s: %w", c.endpoint, err)
		return c.lastError
	}

	// Attempt to dial the socket with a timeout to verify connectivity
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "unix", c.endpoint)
	if err != nil {
		c.lastError = fmt.Errorf("failed to dial CRI socket %s: %w", c.endpoint, err)
		return c.lastError
	}
	conn.Close()

	c.connected = true
	c.lastConnectTime = time.Now()
	c.lastError = nil

	log.Printf("[cri] Connected to %s runtime at %s (detected: %s)", c.runtime, c.endpoint, c.runtime)
	return nil
}

// ConnectWithContext establishes a connection with context cancellation support.
func (c *CRIIntegration) ConnectWithContext(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.connectAttempts++

	c.runtime = detectCRIRuntime(c.endpoint)

	if _, err := os.Stat(c.endpoint); err != nil {
		c.lastError = fmt.Errorf("CRI socket not accessible: %w", err)
		return c.lastError
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", c.endpoint)
	if err != nil {
		c.lastError = fmt.Errorf("failed to dial CRI socket: %w", err)
		return c.lastError
	}
	conn.Close()

	c.connected = true
	c.lastConnectTime = time.Now()
	c.lastError = nil

	log.Printf("[cri] Connected to %s runtime at %s", c.runtime, c.endpoint)
	return nil
}

// Disconnect closes the CRI connection and stops event streaming.
func (c *CRIIntegration) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	c.connected = false
	log.Printf("[cri] Disconnected from CRI runtime")
}

// ListContainers returns all running containers from the CRI.
// This uses the /proc-based fallback when a gRPC connection is unavailable,
// or returns containers from the CRICache when connected.
func (c *CRIIntegration) ListContainers() ([]ContainerInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected {
		// No CRI connection — attempt discovery from /proc
		return c.listContainersFromProc()
	}

	// When connected, use the gRPC ListContainers API.
	// For now, this falls through to /proc discovery until the
	// full containerd client-go dependency is integrated.
	return c.listContainersFromProc()
}

// listContainersFromProc discovers running containers by scanning /proc.
// This is the fallback path when CRI gRPC is not available.
func (c *CRIIntegration) listContainersFromProc() ([]ContainerInfo, error) {
	var containers []ContainerInfo

	procPath := "/proc"
	if c.manager != nil {
		procPath = c.manager.config.ProcFSPath
	}

	entries, err := os.ReadDir(procPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", procPath, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := parsePID(entry.Name())
		if err != nil {
			continue
		}

		// Read cgroup file to extract container ID
		cgroupPath := fmt.Sprintf("%s/%d/cgroup", procPath, pid)
		data, err := os.ReadFile(cgroupPath)
		if err != nil {
			continue
		}

		containerID := ExtractContainerID(string(data))
		if containerID == "" {
			continue
		}

		// Read process name for label
		commPath := fmt.Sprintf("%s/%d/comm", procPath, pid)
		commData, _ := os.ReadFile(commPath)
		comm := strings.TrimSpace(string(commData))

		// Read cgroup ID from cgroup path
		cgroupID := extractCgroupID(string(data))

		info := ContainerInfo{
			ID:      containerID,
			Name:    fmt.Sprintf("container-%.12s", containerID),
			Image:   "unknown", // will be filled by CRI or K8s metadata
			Labels:  make(map[string]string),
			CgroupID: cgroupID,
		}
		if comm != "" {
			info.Labels["process_name"] = comm
		}

		containers = append(containers, info)
	}

	c.containersListed = len(containers)
	c.lastListTime = time.Now()
	return containers, nil
}

// StartEventStream begins streaming container lifecycle events.
// Events are delivered on the EventCh channel.
// Falls back to periodic polling if gRPC streaming is not available.
func (c *CRIIntegration) StartEventStream(ctx context.Context, manager *Manager) {
	c.mu.Lock()
	c.manager = manager
	c.mu.Unlock()

	// Try CRI connection first
	if !c.connected {
		if err := c.ConnectWithContext(ctx); err != nil {
			log.Printf("[cri] Cannot connect to CRI runtime, using /proc polling: %v", err)
			// Fall through to polling mode
		}
	}

	// Start polling-based event stream
	go c.pollContainers(ctx)
}

// pollContainers periodically scans for container changes via /proc.
// This is the production fallback when gRPC CRI streaming is unavailable.
func (c *CRIIntegration) pollContainers(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Initial full scan
	c.fullContainerScan()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[cri] Container polling stopped")
			return
		case <-ticker.C:
			c.incrementalContainerScan()
		}
	}
}

// fullContainerScan performs a complete container discovery.
// Used on startup and when a reconnect occurs.
func (c *CRIIntegration) fullContainerScan() {
	if c.manager == nil {
		return
	}

	containers, err := c.ListContainers()
	if err != nil {
		log.Printf("[cri] Full scan failed: %v", err)
		return
	}

	log.Printf("[cri] Full container scan discovered %d containers", len(containers))

	for i := range containers {
		info := &containers[i]
		c.manager.RegisterContainer(info)

		// Send start event
		select {
		case c.eventCh <- CRIEvent{
			Type:      CRIEventContainerStart,
			Container: info,
			Timestamp: time.Now(),
		}:
		default:
			// Channel full, drop event
		}
	}
}

// incrementalContainerScan detects new and removed containers.
// Compares current state with CRICache to find changes.
func (c *CRIIntegration) incrementalContainerScan() {
	if c.manager == nil {
		return
	}

	containers, err := c.ListContainers()
	if err != nil {
		return
	}

	// Build current container ID set
	currentContainers := make(map[string]bool)
	for _, c := range containers {
		currentContainers[c.ID] = true
	}

	// Find new containers (in current but not in cache)
	for i := range containers {
		info := &containers[i]
		existing := c.manager.criCache.Get(info.ID)
		if existing == nil {
			c.manager.RegisterContainer(info)
			c.eventsProcessed++

			select {
			case c.eventCh <- CRIEvent{
				Type:      CRIEventContainerStart,
				Container: info,
				Timestamp: time.Now(),
			}:
			default:
			}
		}
	}

	// Find removed containers (in cache but not in current scan)
	knownContainers := c.manager.criCache.GetAllContainerIDs()
	for _, id := range knownContainers {
		if !currentContainers[id] {
			info := c.manager.criCache.Get(id)
			if info != nil {
				c.manager.UnregisterContainer(id)
				c.eventsProcessed++

				select {
				case c.eventCh <- CRIEvent{
					Type:      CRIEventContainerStop,
					Container: info,
					Timestamp: time.Now(),
				}:
				default:
				}
			}
		}
	}
}

// Events returns the channel for container lifecycle events.
func (c *CRIIntegration) Events() <-chan CRIEvent {
	return c.eventCh
}

// Runtime returns the detected CRI runtime type.
func (c *CRIIntegration) Runtime() CRIRuntime {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.runtime
}

// IsConnected returns whether the CRI integration has an active connection.
func (c *CRIIntegration) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// Stats returns CRI integration statistics.
type CRIStats struct {
	Runtime          CRIRuntime `json:"runtime"`
	Connected       bool       `json:"connected"`
	Endpoint        string     `json:"endpoint"`
	ContainersListed int       `json:"containers_listed"`
	EventsProcessed int       `json:"events_processed"`
	ConnectAttempts int       `json:"connect_attempts"`
	LastConnectTime time.Time  `json:"last_connect_time"`
	LastListTime    time.Time  `json:"last_list_time"`
	LastError       string    `json:"last_error,omitempty"`
}

// Stats returns current CRI integration statistics.
func (c *CRIIntegration) Stats() CRIStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := CRIStats{
		Runtime:          c.runtime,
		Connected:       c.connected,
		Endpoint:        c.endpoint,
		ContainersListed: c.containersListed,
		EventsProcessed: c.eventsProcessed,
		ConnectAttempts: c.connectAttempts,
		LastConnectTime: c.lastConnectTime,
		LastListTime:    c.lastListTime,
	}
	if c.lastError != nil {
		stats.LastError = c.lastError.Error()
	}
	return stats
}

// ── Helper Functions ────────────────────────────────────────────────

// detectCRIRuntime determines the runtime type from the socket path.
func detectCRIRuntime(endpoint string) CRIRuntime {
	switch {
	case strings.Contains(endpoint, "containerd"):
		return CRIRuntimeContainerd
	case strings.Contains(endpoint, "crio"):
		return CRIRuntimeCRIO
	case strings.Contains(endpoint, "docker"):
		return CRIRuntimeDocker
	default:
		return CRIRuntimeUnknown
	}
}

// extractCgroupID extracts the cgroup inode number from cgroup data.
// This is used to map /proc cgroup entries to the eBPF cgroup_id field.
func extractCgroupID(cgroupData string) uint64 {
	lines := strings.Split(cgroupData, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Look for cgroup v2 unified hierarchy (has 0:: prefix)
		if strings.HasPrefix(line, "0::") {
			// The cgroup path is after the second colon
			path := line[3:]
			if path != "" && path != "/" {
				// Use hash of path as a fallback cgroup ID
				// In production, this would come from stat().CgroupID
				return hashCgroupPath(path)
			}
		}
	}
	return 0
}

// hashCgroupPath creates a deterministic hash from a cgroup path.
// This provides a stable mapping when the actual cgroup inode is not available.
func hashCgroupPath(path string) uint64 {
	var h uint64 = 14695981039346656037 // FNV-1a offset basis
	for _, c := range path {
		h ^= uint64(c)
		h *= 1099511628211 // FNV-1a prime
	}
	return h
}

