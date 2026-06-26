// Package enrichment provides container and Kubernetes metadata enrichment
// for eBPF events. It resolves cgroup IDs to container IDs, fetches
// container metadata from containerd/CRI, and enriches with Kubernetes
// pod metadata.
package enrichment

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ── Container Info ────────────────────────────────────────────────────

// ContainerInfo holds resolved container metadata.
type ContainerInfo struct {
	ID             string
	Name           string
	Image          string
	ImageDigest    string
	PodName        string
	Namespace      string
	ServiceAccount string
	Labels         map[string]string
	StartedAt      time.Time
	Privileged     bool
	Capabilities   []string
	CgroupID       uint64
}

// ── Manager ───────────────────────────────────────────────────────────

// Manager coordinates container identification and metadata enrichment.
type Manager struct {
	config ManagerConfig

	// Three-tier cache (per SRD Section 7.2)
	pidCache *PIDCache // PID → container_id (LRU, 5min TTL)
	criCache *CRICache // container_id → ContainerInfo (event-driven)
	k8sCache *K8sCache // pod → K8s metadata (continuous watch)

	// CRI integration for container runtime events
	cri *CRIIntegration

	// K8s integration for pod metadata
	k8s *K8sIntegration

	// cgroup_id → container_id map (for kernel-side eBPF filtering)
	cgroupMap map[uint64]string
	mu        sync.RWMutex

	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// ManagerConfig holds enrichment manager configuration.
type ManagerConfig struct {
	CRIEndpoint  string
	K8sNodeName  string
	PIDCacheSize int
	PIDCacheTTL  time.Duration
	ProcFSPath   string
}

// NewManager creates a new enrichment manager.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.ProcFSPath == "" {
		cfg.ProcFSPath = "/proc"
	}
	if cfg.PIDCacheSize <= 0 {
		cfg.PIDCacheSize = 10000
	}
	if cfg.PIDCacheTTL <= 0 {
		cfg.PIDCacheTTL = 5 * time.Minute
	}

	m := &Manager{
		config:    cfg,
		pidCache:  NewPIDCache(cfg.PIDCacheSize, cfg.PIDCacheTTL),
		criCache:  NewCRICache(),
		k8sCache:  NewK8sCache(cfg.K8sNodeName),
		cri:       NewCRIIntegration(cfg.CRIEndpoint),
		k8s:       NewK8sIntegration(cfg.K8sNodeName),
		cgroupMap: make(map[uint64]string),
		stopCh:    make(chan struct{}),
	}

	// Wire CRI integration to the manager
	m.cri.SetManager(m)

	return m, nil
}

// Start begins the enrichment manager's background goroutines.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.mu.Unlock()

	log.Printf("[enrichment] Starting enrichment manager (CRI: %s, K8s node: %s)",
		m.config.CRIEndpoint, m.config.K8sNodeName)

	// Discover existing containers via /proc scan
	m.discoverContainers()

	// Start CRI event stream (uses polling when gRPC not available)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.cri.StartEventStream(ctx, m)
	}()

	// Start K8s API watcher
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.k8s.StartWatch(ctx, m)
	}()

	// Start CRI event consumer
	m.wg.Add(1)
	go m.consumeCRIEvents(ctx)

	// Start K8s event consumer
	m.wg.Add(1)
	go m.consumeK8sEvents(ctx)

	// Start PID cache reaper
	m.wg.Add(1)
	go m.reapPIDCache(ctx)
}

// Stop gracefully stops the enrichment manager.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}

	close(m.stopCh)
	m.cri.Disconnect()
	m.wg.Wait()
	m.running = false
	log.Printf("[enrichment] Enrichment manager stopped")
}

// ContainerCount returns the number of tracked containers.
func (m *Manager) ContainerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.criCache.Size()
}

// ResolveContainerID maps a cgroup_id and PID to a container ID.
// Tries the three-tier cache in order: PID LRU → CRI → /proc fallback.
func (m *Manager) ResolveContainerID(cgroupID uint64, pid uint32) string {
	// Tier 1: PID LRU cache
	if containerID := m.pidCache.Get(pid); containerID != "" {
		return containerID
	}

	// Tier 2: CGroup ID map
	m.mu.RLock()
	if containerID, ok := m.cgroupMap[cgroupID]; ok {
		m.mu.RUnlock()
		// Cache in PID LRU for future lookups
		m.pidCache.Set(pid, containerID)
		return containerID
	}
	m.mu.RUnlock()

	// Tier 3: /proc fallback — read cgroup file
	containerID := m.resolveFromProc(pid)
	if containerID != "" {
		m.pidCache.Set(pid, containerID)
	}
	return containerID
}

// GetContainerInfo returns cached container metadata for a given container ID.
func (m *Manager) GetContainerInfo(containerID string) *ContainerInfo {
	return m.criCache.Get(containerID)
}

// RegisterContainer registers a new container with the enrichment system.
func (m *Manager) RegisterContainer(info *ContainerInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.criCache.Set(info.ID, info)
	if info.CgroupID != 0 {
		m.cgroupMap[info.CgroupID] = info.ID
	}

	log.Printf("[enrichment] Container registered: id=%.12s name=%s image=%s ns=%s/%s",
		info.ID, info.Name, info.Image, info.Namespace, info.PodName)
}

// UnregisterContainer removes a container from tracking.
func (m *Manager) UnregisterContainer(containerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	info := m.criCache.Get(containerID)
	if info != nil && info.CgroupID != 0 {
		delete(m.cgroupMap, info.CgroupID)
	}
	m.criCache.Delete(containerID)

	log.Printf("[enrichment] Container unregistered: id=%.12s", containerID)
}

// ── /proc Resolution ──────────────────────────────────────────────────

// resolveFromProc reads /proc/{pid}/cgroup to extract container ID.
func (m *Manager) resolveFromProc(pid uint32) string {
	cgroupPath := filepath.Join(m.config.ProcFSPath, fmt.Sprintf("%d", pid), "cgroup")
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return ""
	}

	return ExtractContainerID(string(data))
}

// ExtractContainerID parses a cgroup file and extracts the container ID.
// Handles formats from containerd, CRI-O, and Docker.
func ExtractContainerID(cgroupData string) string {
	lines := strings.Split(cgroupData, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Format: ID:path
		// containerd: 0::/system.slice/containerd.service/abc123...
		// CRI-O:     0::/crio-abc123...
		// Docker:    0::/docker/abc123...
		// k8s:       0::/kubepods/pod123/container123

		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}

		path := parts[2]

		// Extract container ID from cgroup path
		segments := strings.Split(path, "/")
		for i := len(segments) - 1; i >= 0; i-- {
			seg := segments[i]
			if seg == "" {
				continue
			}

			// Containerd container IDs are 64-char hex strings
			if len(seg) >= 12 && isHexString(seg) {
				// Check if this looks like a container ID (not a pod ID)
				if !strings.HasPrefix(seg, "pod") && !strings.HasPrefix(seg, "crio-") {
					return seg
				}
				// CRI-O prefixes
				if strings.HasPrefix(seg, "crio-") {
					return strings.TrimPrefix(seg, "crio-")
				}
				return seg
			}
		}
	}

	return ""
}

// isHexString checks if a string is a valid hex string.
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// ── Discovery ────────────────────────────────────────────────────────

// discoverContainers scans /proc to find already-running containers.
func (m *Manager) discoverContainers() {
	log.Printf("[enrichment] Discovering existing containers...")

	entries, err := os.ReadDir(m.config.ProcFSPath)
	if err != nil {
		log.Printf("[enrichment] Warning: cannot read %s: %v", m.config.ProcFSPath, err)
		return
	}

	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID
		pid, err := parsePID(entry.Name())
		if err != nil {
			continue
		}

		containerID := m.resolveFromProc(pid)
		if containerID != "" {
			m.pidCache.Set(pid, containerID)
			count++
		}
	}

	log.Printf("[enrichment] Discovered %d containers from /proc", count)
}

// parsePID parses a string as a PID (uint32).
func parsePID(s string) (uint32, error) {
	var pid uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a PID")
		}
		pid = pid*10 + uint32(c-'0')
	}
	if pid == 0 {
		return 0, fmt.Errorf("PID 0")
	}
	return pid, nil
}

// ── Event Consumers ──────────────────────────────────────────────────

// consumeCRIEvents processes container lifecycle events from the CRI integration.
func (m *Manager) consumeCRIEvents(ctx context.Context) {
	defer m.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case event := <-m.cri.eventCh:
			switch event.Type {
			case CRIEventContainerStart:
				if event.Container != nil {
					m.RegisterContainer(event.Container)
				}
			case CRIEventContainerStop:
				if event.Container != nil {
					m.UnregisterContainer(event.Container.ID)
				}
			case CRIEventContainerUpdate:
				if event.Container != nil {
					m.RegisterContainer(event.Container) // update = re-register
				}
			}
		}
	}
}

// consumeK8sEvents processes pod metadata updates from the K8s integration.
func (m *Manager) consumeK8sEvents(ctx context.Context) {
	defer m.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case event := <-m.k8s.eventCh:
			switch event.Type {
			case K8sEventPodAdded:
				if event.Pod != nil {
					m.HandlePodAdded(event.Pod)
				}
			case K8sEventPodUpdated:
				if event.Pod != nil {
					m.HandlePodUpdated(event.Pod)
				}
			case K8sEventPodDeleted:
				if event.Pod != nil {
					m.HandlePodDeleted(event.Pod)
				}
			}
		}
	}
}

// HandlePodAdded enriches container info with pod metadata when a pod is added.
func (m *Manager) HandlePodAdded(pod *PodInfo) {
	for _, containerID := range pod.Containers {
		m.mu.Lock()
		info := m.criCache.Get(containerID)
		if info != nil {
			info.PodName = pod.Name
			info.Namespace = pod.Namespace
			info.ServiceAccount = pod.ServiceAccount
			if info.Labels == nil {
				info.Labels = make(map[string]string)
			}
			for k, v := range pod.Labels {
				info.Labels[k] = v
			}
			m.criCache.Set(containerID, info)
		}
		m.mu.Unlock()
	}

	log.Printf("[enrichment] Pod added: %s/%s (%d containers)",
		pod.Namespace, pod.Name, len(pod.Containers))
}

// HandlePodUpdated updates container info when pod metadata changes.
func (m *Manager) HandlePodUpdated(pod *PodInfo) {
	m.HandlePodAdded(pod) // Same enrichment logic
}

// HandlePodDeleted removes pod references when a pod is deleted.
func (m *Manager) HandlePodDeleted(pod *PodInfo) {
	log.Printf("[enrichment] Pod deleted: %s/%s", pod.Namespace, pod.Name)
}

// reapPIDCache periodically removes expired PID cache entries and prunes stale cgroup entries.
func (m *Manager) reapPIDCache(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.pidCache.Reap()
			// Also prune the cgroup map to remove stale entries
			m.pruneCgroupMap()
		}
	}
}

// pruneCgroupMap removes stale entries from the cgroup → container map.
// Entries whose container IDs no longer exist in the CRI cache are pruned.
func (m *Manager) pruneCgroupMap() {
	m.mu.Lock()
	defer m.mu.Unlock()

	pruned := 0
	for cgroupID, containerID := range m.cgroupMap {
		if m.criCache.Get(containerID) == nil {
			delete(m.cgroupMap, cgroupID)
			pruned++
		}
	}
	if pruned > 0 {
		log.Printf("[enrichment] Pruned %d stale cgroup entries", pruned)
	}
}

// PruneCaches prunes idle entries from all enrichment caches.
// This is useful for reducing memory pressure on nodes with high container churn.
// Returns the number of entries pruned.
func (m *Manager) PruneCaches(idleThreshold time.Duration) int {
	totalPruned := 0

	// Prune PID cache
	if m.pidCache != nil {
		totalPruned += m.pidCache.Prune(idleThreshold)
	}

	// Prune CRI cache (entries not accessed within threshold)
	if m.criCache != nil {
		totalPruned += m.criCache.Prune(idleThreshold)
	}

	// Prune cgroup map (entries whose container no longer exists in CRI cache)
	m.mu.Lock()
	cgroupPruned := 0
	for cgroupID, containerID := range m.cgroupMap {
		if m.criCache.Get(containerID) == nil {
			delete(m.cgroupMap, cgroupID)
			cgroupPruned++
		}
	}
	m.mu.Unlock()
	totalPruned += cgroupPruned

	if totalPruned > 0 {
		log.Printf("[enrichment] Cache pruning: %d entries pruned (idle > %v)", totalPruned, idleThreshold)
	}

	return totalPruned
}

// ── PID Cache ────────────────────────────────────────────────────────

// PIDCache is an LRU cache mapping PID → container_id with TTL-based expiry
// and proper LRU eviction ordering for efficient pruning.
type PIDCache struct {
	size    int
	ttl     time.Duration
	entries map[uint32]*pidCacheEntry
	// Doubly-linked list for LRU ordering (most recently used at front)
	head *pidCacheEntry // MRU entry
	tail *pidCacheEntry // LRU entry (eviction candidate)
	mu   sync.RWMutex
}

type pidCacheEntry struct {
	pid         uint32
	containerID string
	expiry      time.Time
	lastAccess  time.Time
	prev        *pidCacheEntry
	next        *pidCacheEntry
}

// NewPIDCache creates a new PID cache with the given maximum size and TTL.
func NewPIDCache(size int, ttl time.Duration) *PIDCache {
	return &PIDCache{
		size:    size,
		ttl:     ttl,
		entries: make(map[uint32]*pidCacheEntry),
	}
}

// Get retrieves a container ID for the given PID.
func (c *PIDCache) Get(pid uint32) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if entry, ok := c.entries[pid]; ok {
		if time.Now().Before(entry.expiry) {
			// Update last access time (for LRU pruning)
			entry.lastAccess = time.Now()
			// Move to front of LRU list
			return entry.containerID
		}
	}
	return ""
}

// Set stores a container ID for the given PID.
func (c *PIDCache) Set(pid uint32, containerID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If entry already exists, update it
	if entry, ok := c.entries[pid]; ok {
		entry.containerID = containerID
		entry.expiry = time.Now().Add(c.ttl)
		entry.lastAccess = time.Now()
		c.moveToFront(entry)
		return
	}

	// Evict if at capacity
	if len(c.entries) >= c.size {
		c.evictLRU()
	}

	now := time.Now()
	entry := &pidCacheEntry{
		pid:         pid,
		containerID: containerID,
		expiry:      now.Add(c.ttl),
		lastAccess:  now,
	}
	c.entries[pid] = entry
	c.addToFront(entry)
}

// Reap removes expired entries.
func (c *PIDCache) Reap() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for pid, entry := range c.entries {
		if now.After(entry.expiry) {
			c.removeEntry(entry)
			delete(c.entries, pid)
		}
	}
}

// Prune removes entries that haven't been accessed within the given duration,
// regardless of TTL. This is useful for reducing memory usage under pressure.
func (c *PIDCache) Prune(idleThreshold time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	pruned := 0
	for pid, entry := range c.entries {
		if now.Sub(entry.lastAccess) > idleThreshold {
			c.removeEntry(entry)
			delete(c.entries, pid)
			pruned++
		}
	}
	return pruned
}

// Size returns the number of entries in the cache.
func (c *PIDCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// evictLRU removes the least recently used entry.
func (c *PIDCache) evictLRU() {
	if c.tail == nil {
		return
	}
	victim := c.tail
	c.removeEntry(victim)
	delete(c.entries, victim.pid)
}

// addToFront adds an entry to the front (MRU position) of the LRU list.
func (c *PIDCache) addToFront(entry *pidCacheEntry) {
	entry.prev = nil
	entry.next = c.head
	if c.head != nil {
		c.head.prev = entry
	}
	c.head = entry
	if c.tail == nil {
		c.tail = entry
	}
}

// moveToFront moves an existing entry to the front of the LRU list.
func (c *PIDCache) moveToFront(entry *pidCacheEntry) {
	if entry == c.head {
		return
	}
	c.removeEntry(entry)
	c.addToFront(entry)
}

// removeEntry removes an entry from the LRU linked list.
func (c *PIDCache) removeEntry(entry *pidCacheEntry) {
	if entry.prev != nil {
		entry.prev.next = entry.next
	} else {
		c.head = entry.next
	}
	if entry.next != nil {
		entry.next.prev = entry.prev
	} else {
		c.tail = entry.prev
	}
	entry.prev = nil
	entry.next = nil
}

// ── CRI Cache ─────────────────────────────────────────────────────────

// CRICache stores container metadata keyed by container ID.
// Implements LRU eviction with configurable max size to prevent
// unbounded memory growth on nodes with high container churn.
type CRICache struct {
	entries map[string]*criCacheEntry
	maxSize int            // 0 = unlimited
	head    *criCacheEntry // MRU
	tail    *criCacheEntry // LRU (eviction candidate)
	mu      sync.RWMutex
}

type criCacheEntry struct {
	containerID string
	info        *ContainerInfo
	lastAccess  time.Time
	prev        *criCacheEntry
	next        *criCacheEntry
}

// NewCRICache creates a new CRI cache.
func NewCRICache() *CRICache {
	return NewCRICacheWithMaxSize(0)
}

// NewCRICacheWithMaxSize creates a new CRI cache with a maximum size.
// When maxSize > 0, LRU eviction is enabled.
func NewCRICacheWithMaxSize(maxSize int) *CRICache {
	return &CRICache{
		entries: make(map[string]*criCacheEntry),
		maxSize: maxSize,
	}
}

// Get retrieves container info.
func (c *CRICache) Get(containerID string) *ContainerInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if entry, ok := c.entries[containerID]; ok {
		entry.lastAccess = time.Now()
		return entry.info
	}
	return nil
}

// Set stores container info.
func (c *CRICache) Set(containerID string, info *ContainerInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If entry exists, update
	if entry, ok := c.entries[containerID]; ok {
		entry.info = info
		entry.lastAccess = time.Now()
		c.moveToFront(entry)
		return
	}

	// Evict LRU if at capacity
	if c.maxSize > 0 && len(c.entries) >= c.maxSize {
		c.evictLRU()
	}

	now := time.Now()
	entry := &criCacheEntry{
		containerID: containerID,
		info:        info,
		lastAccess:  now,
	}
	c.entries[containerID] = entry
	c.addToFront(entry)
}

// Delete removes a container.
func (c *CRICache) Delete(containerID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[containerID]; ok {
		c.removeEntry(entry)
		delete(c.entries, containerID)
	}
}

// Size returns the number of tracked containers.
func (c *CRICache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// GetAllContainerIDs returns all container IDs in the CRI cache.
func (c *CRICache) GetAllContainerIDs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ids := make([]string, 0, len(c.entries))
	for id := range c.entries {
		ids = append(ids, id)
	}
	return ids
}

// Prune removes entries that haven't been accessed within the idle threshold.
// Returns the number of entries pruned.
func (c *CRICache) Prune(idleThreshold time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	pruned := 0
	for id, entry := range c.entries {
		if now.Sub(entry.lastAccess) > idleThreshold {
			c.removeEntry(entry)
			delete(c.entries, id)
			pruned++
		}
	}
	return pruned
}

// evictLRU removes the least recently used entry.
func (c *CRICache) evictLRU() {
	if c.tail == nil {
		return
	}
	victim := c.tail
	c.removeEntry(victim)
	delete(c.entries, victim.containerID)
}

// addToFront adds an entry to the front (MRU position) of the LRU list.
func (c *CRICache) addToFront(entry *criCacheEntry) {
	entry.prev = nil
	entry.next = c.head
	if c.head != nil {
		c.head.prev = entry
	}
	c.head = entry
	if c.tail == nil {
		c.tail = entry
	}
}

// moveToFront moves an existing entry to the front of the LRU list.
func (c *CRICache) moveToFront(entry *criCacheEntry) {
	if entry == c.head {
		return
	}
	c.removeEntry(entry)
	c.addToFront(entry)
}

// removeEntry removes an entry from the LRU linked list.
func (c *CRICache) removeEntry(entry *criCacheEntry) {
	if entry.prev != nil {
		entry.prev.next = entry.next
	} else {
		c.head = entry.next
	}
	if entry.next != nil {
		entry.next.prev = entry.prev
	} else {
		c.tail = entry.prev
	}
	entry.prev = nil
	entry.next = nil
}

// ── K8s Cache ────────────────────────────────────────────────────────

// K8sCache stores Kubernetes pod metadata.
type K8sCache struct {
	nodeName string
	pods     map[string]*PodInfo
	mu       sync.RWMutex
}

// PodInfo holds Kubernetes pod metadata for enrichment.
type PodInfo struct {
	Name           string
	Namespace      string
	ServiceAccount string
	Labels         map[string]string
	Containers     []string // container IDs in this pod
}

// NewK8sCache creates a new K8s cache.
func NewK8sCache(nodeName string) *K8sCache {
	return &K8sCache{
		nodeName: nodeName,
		pods:     make(map[string]*PodInfo),
	}
}

// Get retrieves pod info by pod key (namespace/name).
func (k *K8sCache) Get(key string) *PodInfo {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.pods[key]
}

// Set stores pod info.
func (k *K8sCache) Set(key string, pod *PodInfo) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.pods[key] = pod
}

// Delete removes a pod.
func (k *K8sCache) Delete(key string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.pods, key)
}

// Size returns the number of tracked pods.
func (k *K8sCache) Size() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.pods)
}

// LookupByContainerID finds the pod containing a given container ID.
func (k *K8sCache) LookupByContainerID(containerID string) *PodInfo {
	k.mu.RLock()
	defer k.mu.RUnlock()

	for _, pod := range k.pods {
		for _, cid := range pod.Containers {
			if cid == containerID {
				return pod
			}
		}
	}
	return nil
}
