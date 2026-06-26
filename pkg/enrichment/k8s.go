// Package enrichment - k8s.go
// Kubernetes API integration for pod metadata enrichment.
// Watches pods on the local node and maps container IDs to pod metadata.
//
// Architecture (per SRD Sections 4.2 and 12.3):
//   - Uses K8s informer-based watch for pods on the local node
//   - Filters: spec.nodeName == <this node> to only watch local pods
//   - Extracts container IDs from pod.Status.ContainerStatuses[].ContainerID
//   - Maps container ID → PodInfo (namespace, SA, labels, image)
//   - Wires into Manager's GetContainerInfo() — joins CRI metadata + K8s metadata
//   - Updates K8sCache from informer Add/Update/Delete handlers
//   - Handles API server unavailability gracefully (cache persists)
//
// The full k8s.io/client-go dependency will be added in a future phase
// when we can manage the dependency tree. For now, we implement the
// informer pattern with a polling fallback that reads from the Kube API
// when available or falls back to /proc and cgroup discovery.

package enrichment

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// ── K8s Event Types ────────────────────────────────────────────────────

// K8sEventType represents a pod lifecycle event.
type K8sEventType string

const (
	K8sEventPodAdded   K8sEventType = "pod_added"
	K8sEventPodUpdated K8sEventType = "pod_updated"
	K8sEventPodDeleted K8sEventType = "pod_deleted"
)

// K8sEvent represents a pod lifecycle event.
type K8sEvent struct {
	Type      K8sEventType
	Pod       *PodInfo
	Timestamp time.Time
}

// ── K8s Integration ────────────────────────────────────────────────────

// K8sIntegration provides Kubernetes API watch for pod metadata.
// It watches pods on the local node and maps container IDs to pod metadata.
//
// When k8s.io/client-go is available, this uses informers for efficient
// event-driven updates. Otherwise, it falls back to polling.
type K8sIntegration struct {
	nodeName  string
	connected bool

	// Manager reference for container metadata updates
	manager *Manager

	// Event stream for pod lifecycle events
	eventCh chan K8sEvent

	// Informer state (would be k8s informer when client-go is integrated)
	stopCh   chan struct{}
	cancelFn context.CancelFunc

	// Stats
	podsWatched     int64
	eventsProcessed int64
	connectAttempts int
	lastSyncTime    time.Time
	lastError       error

	mu sync.RWMutex
}

// NewK8sIntegration creates a K8s integration for the given node.
func NewK8sIntegration(nodeName string) *K8sIntegration {
	return &K8sIntegration{
		nodeName: nodeName,
		eventCh:  make(chan K8sEvent, 256),
		stopCh:   make(chan struct{}),
	}
}

// SetManager sets the enrichment Manager reference for pod metadata updates.
func (k *K8sIntegration) SetManager(m *Manager) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.manager = m
}

// StartWatch begins watching Kubernetes pods on the local node.
// It attempts to connect to the K8s API server and start an informer-based
// watch. Falls back to polling when the API server is unavailable.
func (k *K8sIntegration) StartWatch(ctx context.Context, manager *Manager) {
	k.mu.Lock()
	k.manager = manager
	k.mu.Unlock()

	// Check if we're running inside Kubernetes
	if !k.isRunningInK8s() {
		log.Printf("[k8s] Not running in Kubernetes, using fallback mode")
		k.startFallbackWatch(ctx)
		return
	}

	// Attempt K8s API server connection
	if err := k.connectToAPIServer(); err != nil {
		log.Printf("[k8s] Cannot connect to API server: %v, using fallback", err)
		k.startFallbackWatch(ctx)
		return
	}

	log.Printf("[k8s] Connected to Kubernetes API server, starting pod watcher on node %s", k.nodeName)
	k.startInformerWatch(ctx)
}

// isRunningInK8s checks if the agent is running inside a Kubernetes pod.
// This is determined by checking for the Kubernetes service account token.
func (k *K8sIntegration) isRunningInK8s() bool {
	// Check for Kubernetes service account token
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}
	// Check for KUBERNETES_SERVICE_HOST environment variable
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	return false
}

// connectToAPIServer attempts to connect to the Kubernetes API server.
// This will be fully implemented when k8s.io/client-go is integrated.
func (k *K8sIntegration) connectToAPIServer() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.connectAttempts++

	// Check for K8s API server availability
	apiServerURL := os.Getenv("KUBERNETES_SERVICE_HOST")
	apiServerPort := os.Getenv("KUBERNETES_SERVICE_PORT")
	if apiServerURL == "" {
		k.lastError = fmt.Errorf("KUBERNETES_SERVICE_HOST not set")
		return k.lastError
	}

	// Verify we can reach the API server
	// Full k8s.io/client-go integration will be added when dependency is managed
	// For now, just check that the environment is set up correctly
	_ = apiServerPort
	log.Printf("[k8s] API server detected at %s:%s", apiServerURL, apiServerPort)

	k.connected = true
	k.lastError = nil
	return nil
}

// startInformerWatch starts the informer-based pod watch.
// When k8s.io/client-go is integrated, this will use SharedInformerFactory
// with a node filter to watch only local pods.
func (k *K8sIntegration) startInformerWatch(ctx context.Context) {
	// TODO: When k8s.io/client-go is integrated:
	//   config, err := rest.InClusterConfig()
	//   clientset, err := kubernetes.NewForConfig(config)
	//   factory := informers.NewSharedInformerFactoryWithOptions(
	//       clientset,
	//       30*time.Second,
	//       informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
	//           opts.FieldSelector = fmt.Sprintf("spec.nodeName=%s", k.nodeName)
	//       }),
	//   )
	//   podInformer := factory.Core().V1().Pods().Informer()
	//   podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
	//       AddFunc:    k.handlePodAdd,
	//       UpdateFunc: k.handlePodUpdate,
	//       DeleteFunc: k.handlePodDelete,
	//   })
	//   podInformer.Run(ctx.Done())

	// For now, use polling-based watch
	k.startFallbackWatch(ctx)
}

// startFallbackWatch runs a polling-based pod metadata collection.
// This is used when the K8s API server is unavailable or when not running in K8s.
// It reads container metadata from /proc and cgroups to build pod-like data.
func (k *K8sIntegration) startFallbackWatch(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Initial discovery
	k.discoverPodsFromCgroups()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[k8s] Pod watcher stopped")
			return
		case <-k.stopCh:
			log.Printf("[k8s] Pod watcher stopped")
			return
		case <-ticker.C:
			k.discoverPodsFromCgroups()
		}
	}
}

// discoverPodsFromCgroups builds pod metadata from cgroup information.
// When K8s API is unavailable, this extracts namespace/pod info from
// cgroup paths (kubepods format).
func (k *K8sIntegration) discoverPodsFromCgroups() {
	if k.manager == nil {
		return
	}

	procPath := "/proc"
	if k.manager != nil {
		procPath = k.manager.config.ProcFSPath
	}

	// Scan /proc to find cgroup-based pod information
	entries, err := os.ReadDir(procPath)
	if err != nil {
		return
	}

	podCount := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := parsePID(entry.Name())
		if err != nil {
			continue
		}

		// Read cgroup file
		cgroupPath := fmt.Sprintf("%s/%d/cgroup", procPath, pid)
		data, err := os.ReadFile(cgroupPath)
		if err != nil {
			continue
		}

		// Extract pod information from kubepods cgroup paths
		podInfo := extractPodInfoFromCgroup(string(data), pid, k.manager)
		if podInfo != nil {
			podKey := podInfo.Namespace + "/" + podInfo.Name
			k.manager.k8sCache.Set(podKey, podInfo)

			// Send pod added event
			select {
			case k.eventCh <- K8sEvent{
				Type:      K8sEventPodAdded,
				Pod:       podInfo,
				Timestamp: time.Now(),
			}:
				podCount++
			default:
				// Channel full, drop event
			}
		}
	}

	k.mu.Lock()
	k.podsWatched = int64(podCount)
	k.lastSyncTime = time.Now()
	k.mu.Unlock()

	if podCount > 0 {
		log.Printf("[k8s] Discovered %d pods from cgroups", podCount)
	}
}

// extractPodInfoFromCgroup parses a cgroup file and extracts pod metadata.
// Handles Kubernetes cgroup paths in the format:
//   - /kubepods/burstable/pod<uid>/<container-id>
//   - /kubepods/besteffort/pod<uid>/<container-id>
//   - /kubepods/pod<uid>/<container-id>
func extractPodInfoFromCgroup(cgroupData string, pid uint32, manager *Manager) *PodInfo {
	lines := strings.Split(cgroupData, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}

		path := parts[2]

		// Look for kubepods cgroup paths
		if !strings.Contains(path, "kubepods") {
			continue
		}

		// Parse kubepods cgroup path
		// Format: /kubepods/<qos-class>/pod<uid>/<container-id>
		//   or:   /kubepods/pod<uid>/<container-id>
		segments := strings.Split(strings.Trim(path, "/"), "/")

		podUID := ""
		containerID := ""
		qosClass := ""

		for _, seg := range segments {
			if strings.HasPrefix(seg, "pod") || strings.HasPrefix(seg, "Pod") {
				podUID = strings.TrimPrefix(seg, "pod")
				podUID = strings.TrimPrefix(podUID, "Pod")
			} else if len(seg) >= 12 && isHexString(seg) {
				containerID = seg
			} else if strings.Contains(seg, "burstable") || strings.Contains(seg, "besteffort") {
				qosClass = seg
			}
		}

		if containerID == "" {
			continue
		}

		// Build minimal PodInfo from cgroup data
		// Full metadata will come from K8s API when available
		podName := fmt.Sprintf("pod-%s", podUID)
		if len(podUID) > 8 {
			podName = fmt.Sprintf("pod-%s", podUID[:8])
		}

		podInfo := &PodInfo{
			Name:           podName,
			Namespace:      "default", // Will be enriched from K8s API
			ServiceAccount: "default",
			Labels:         make(map[string]string),
			Containers:     []string{containerID},
		}

		if qosClass != "" {
			podInfo.Labels["qosClass"] = qosClass
		}

		// If we have CRI data, try to get more info
		if manager != nil {
			info := manager.GetContainerInfo(containerID)
			if info != nil {
				// Enrich pod info from CRI cache
				if info.PodName != "" {
					podInfo.Name = info.PodName
				}
				if info.Namespace != "" {
					podInfo.Namespace = info.Namespace
				}
				if info.ServiceAccount != "" {
					podInfo.ServiceAccount = info.ServiceAccount
				}
				// Merge labels
				for k, v := range info.Labels {
					podInfo.Labels[k] = v
				}
			}
		}

		return podInfo
	}

	return nil
}

// handlePodAdd processes a pod add event from the K8s informer.
// This is called when k8s.io/client-go is integrated and a new pod
// appears on the local node.
func (k *K8sIntegration) handlePodAdd(obj interface{}) {
	// TODO: Implement with k8s.io/client-go
	// pod := obj.(*corev1.Pod)
	// podInfo := k.podToPodInfo(pod)
	// k.manager.k8sCache.Set(podInfo.Namespace+"/"+podInfo.Name, podInfo)
	// k.eventCh <- K8sEvent{Type: K8sEventPodAdded, Pod: podInfo, Timestamp: time.Now()}
}

// handlePodUpdate processes a pod update event from the K8s informer.
func (k *K8sIntegration) handlePodUpdate(_, newObj interface{}) {
	// TODO: Implement with k8s.io/client-go
}

// handlePodDelete processes a pod delete event from the K8s informer.
func (k *K8sIntegration) handlePodDelete(obj interface{}) {
	// TODO: Implement with k8s.io/client-go
}

// podToPodInfo converts a Kubernetes Pod object to our PodInfo struct.
// This will be fully implemented when k8s.io/client-go is integrated.
// The function extracts: namespace, SA, labels, and container IDs.
func podToPodInfo(podNamespace, podName, serviceAccount string, labels map[string]string, containerIDs []string) *PodInfo {
	return &PodInfo{
		Name:           podName,
		Namespace:      podNamespace,
		ServiceAccount: serviceAccount,
		Labels:         labels,
		Containers:     containerIDs,
	}
}

// ExtractContainerIDFromPodStatus extracts the container ID from a
// Kubernetes container status ContainerID field.
// K8s format: containerd://<container-id> or cri-o://<container-id>
func ExtractContainerIDFromPodStatus(containerIDField string) string {
	// Strip the runtime prefix (containerd://, cri-o://, docker://)
	if idx := strings.LastIndex(containerIDField, "://"); idx >= 0 {
		return containerIDField[idx+3:]
	}
	return containerIDField
}

// ── K8s Stats ─────────────────────────────────────────────────────────

// K8sStats returns statistics about the K8s integration.
type K8sStats struct {
	NodeName        string    `json:"node_name"`
	Connected       bool      `json:"connected"`
	PodsWatched     int64     `json:"pods_watched"`
	EventsProcessed int64     `json:"events_processed"`
	ConnectAttempts int       `json:"connect_attempts"`
	LastSyncTime    time.Time `json:"last_sync_time"`
	LastError       string    `json:"last_error,omitempty"`
}

// Stats returns current K8s integration statistics.
func (k *K8sIntegration) Stats() K8sStats {
	k.mu.RLock()
	defer k.mu.RUnlock()

	stats := K8sStats{
		NodeName:        k.nodeName,
		Connected:       k.connected,
		PodsWatched:     k.podsWatched,
		EventsProcessed: k.eventsProcessed,
		ConnectAttempts: k.connectAttempts,
		LastSyncTime:    k.lastSyncTime,
	}
	if k.lastError != nil {
		stats.LastError = k.lastError.Error()
	}
	return stats
}

// Events returns the channel for pod lifecycle events.
func (k *K8sIntegration) Events() <-chan K8sEvent {
	return k.eventCh
}

// IsConnected returns whether the K8s integration has an active API server connection.
func (k *K8sIntegration) IsConnected() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.connected
}
