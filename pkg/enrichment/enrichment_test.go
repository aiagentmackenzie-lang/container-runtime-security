// Package enrichment_test — unit tests for CRI integration and K8s API watch.
package enrichment_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/securityscarlet/runtime/pkg/enrichment"
)

// ── CRI Integration Tests ──────────────────────────────────────────────

func TestNewCRIIntegration(t *testing.T) {
	cri := enrichment.NewCRIIntegration("/run/containerd/containerd.sock")
	if cri == nil {
		t.Fatal("Expected non-nil CRIIntegration")
	}
}

func TestDetectCRIRuntime_Containerd(t *testing.T) {
	cri := enrichment.NewCRIIntegration("/run/containerd/containerd.sock")
	if cri.Runtime() != enrichment.CRIRuntimeContainerd {
		t.Errorf("Expected containerd runtime, got %s", cri.Runtime())
	}
}

func TestDetectCRIRuntime_CRIO(t *testing.T) {
	cri := enrichment.NewCRIIntegration("/run/crio/crio.sock")
	if cri.Runtime() != enrichment.CRIRuntimeCRIO {
		t.Errorf("Expected cri-o runtime, got %s", cri.Runtime())
	}
}

func TestDetectCRIRuntime_Docker(t *testing.T) {
	cri := enrichment.NewCRIIntegration("/var/run/docker.sock")
	if cri.Runtime() != enrichment.CRIRuntimeDocker {
		t.Errorf("Expected docker runtime, got %s", cri.Runtime())
	}
}

func TestDetectCRIRuntime_Unknown(t *testing.T) {
	cri := enrichment.NewCRIIntegration("/custom/runtime.sock")
	if cri.Runtime() != enrichment.CRIRuntimeUnknown {
		t.Errorf("Expected unknown runtime, got %s", cri.Runtime())
	}
}

func TestCRIIntegration_NotConnectedByDefault(t *testing.T) {
	cri := enrichment.NewCRIIntegration("/run/containerd/containerd.sock")
	if cri.IsConnected() {
		t.Error("CRI should not be connected by default")
	}
}

func TestCRIIntegration_ConnectFailsOnMissingSocket(t *testing.T) {
	cri := enrichment.NewCRIIntegration("/nonexistent/containerd.sock")
	err := cri.Connect()
	if err == nil {
		t.Error("Expected error connecting to nonexistent socket")
	}
}

func TestCRIIntegration_Stats(t *testing.T) {
	cri := enrichment.NewCRIIntegration("/run/containerd/containerd.sock")
	stats := cri.Stats()
	if stats.Runtime != enrichment.CRIRuntimeContainerd {
		t.Errorf("Expected containerd runtime, got %s", stats.Runtime)
	}
	if stats.Connected {
		t.Error("Should not be connected initially")
	}
	if stats.Endpoint != "/run/containerd/containerd.sock" {
		t.Errorf("Unexpected endpoint: %s", stats.Endpoint)
	}
}

func TestCRIIntegration_EventsChannel(t *testing.T) {
	cri := enrichment.NewCRIIntegration("/run/containerd/containerd.sock")
	ch := cri.Events()
	if ch == nil {
		t.Error("Expected non-nil events channel")
	}
}

// ── CRI Event Types Tests ──────────────────────────────────────────────

func TestCRIEventTypes(t *testing.T) {
	types := []enrichment.CRIEventType{
		enrichment.CRIEventContainerStart,
		enrichment.CRIEventContainerStop,
		enrichment.CRIEventContainerUpdate,
	}
	expected := []string{"container_start", "container_stop", "container_update"}

	for i, typ := range types {
		if string(typ) != expected[i] {
			t.Errorf("Expected %s, got %s", expected[i], typ)
		}
	}
}

func TestCRIRuntimeTypes(t *testing.T) {
	if enrichment.CRIRuntimeContainerd != "containerd" {
		t.Errorf("Expected 'containerd', got %s", enrichment.CRIRuntimeContainerd)
	}
	if enrichment.CRIRuntimeCRIO != "cri-o" {
		t.Errorf("Expected 'cri-o', got %s", enrichment.CRIRuntimeCRIO)
	}
	if enrichment.CRIRuntimeDocker != "docker" {
		t.Errorf("Expected 'docker', got %s", enrichment.CRIRuntimeDocker)
	}
}

// ── CRI Container Status Tests ─────────────────────────────────────────

func TestCRIContainerStatuses(t *testing.T) {
	statuses := map[enrichment.CRIContainerStatus]string{
		enrichment.CRIContainerCreated: "created",
		enrichment.CRIContainerRunning:  "running",
		enrichment.CRIContainerExited:   "exited",
		enrichment.CRIContainerUnknown:  "unknown",
	}
	for status, expected := range statuses {
		if string(status) != expected {
			t.Errorf("Expected %s, got %s", expected, status)
		}
	}
}

// ── Manager Integration Tests ──────────────────────────────────────────

func TestManager_NewManager(t *testing.T) {
	mgr, err := enrichment.NewManager(enrichment.ManagerConfig{
		CRIEndpoint:  "/run/containerd/containerd.sock",
		K8sNodeName:  "test-node",
		PIDCacheSize: 100,
		PIDCacheTTL:  1 * time.Minute,
		ProcFSPath:   "/proc",
	})
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	if mgr == nil {
		t.Fatal("Expected non-nil manager")
	}
}

func TestManager_RegisterAndUnregisterContainer(t *testing.T) {
	mgr, _ := enrichment.NewManager(enrichment.ManagerConfig{
		CRIEndpoint: "/run/containerd/containerd.sock",
		K8sNodeName: "test-node",
		ProcFSPath:  "/proc",
	})

	info := &enrichment.ContainerInfo{
		ID:        "abc123def456789",
		Name:      "test-container",
		Image:     "nginx:latest",
		Namespace: "default",
		PodName:   "test-pod",
		CgroupID:  12345,
	}

	// Register
	mgr.RegisterContainer(info)

	// Verify retrieval
	retrieved := mgr.GetContainerInfo("abc123def456789")
	if retrieved == nil {
		t.Fatal("Expected to retrieve registered container")
	}
	if retrieved.Name != "test-container" {
		t.Errorf("Expected name 'test-container', got %s", retrieved.Name)
	}
	if retrieved.Image != "nginx:latest" {
		t.Errorf("Expected image 'nginx:latest', got %s", retrieved.Image)
	}
	if retrieved.Namespace != "default" {
		t.Errorf("Expected namespace 'default', got %s", retrieved.Namespace)
	}

	// Verify container count
	if mgr.ContainerCount() != 1 {
		t.Errorf("Expected 1 container, got %d", mgr.ContainerCount())
	}

	// Unregister
	mgr.UnregisterContainer("abc123def456789")

	// Verify removal
	retrieved = mgr.GetContainerInfo("abc123def456789")
	if retrieved != nil {
		t.Error("Expected nil after unregistration")
	}
	if mgr.ContainerCount() != 0 {
		t.Errorf("Expected 0 containers, got %d", mgr.ContainerCount())
	}
}

func TestManager_ResolveContainerID_CacheHit(t *testing.T) {
	mgr, _ := enrichment.NewManager(enrichment.ManagerConfig{
		ProcFSPath: "/proc",
	})

	info := &enrichment.ContainerInfo{
		ID:       "cached-container-id",
		Name:     "cached",
		CgroupID: 99999,
	}
	mgr.RegisterContainer(info)

	// Resolve via cgroup ID (Tier 2 cache)
	result := mgr.ResolveContainerID(99999, 12345)
	if result != "cached-container-id" {
		t.Errorf("Expected 'cached-container-id', got %q", result)
	}
}

func TestManager_PodEnrichment(t *testing.T) {
	mgr, _ := enrichment.NewManager(enrichment.ManagerConfig{
		ProcFSPath: "/proc",
	})

	// Register a container first
	containerInfo := &enrichment.ContainerInfo{
		ID:       "container-abc123",
		Name:     "app-container",
		Image:    "app:latest",
		CgroupID: 55555,
	}
	mgr.RegisterContainer(containerInfo)

	// Simulate pod enrichment via HandlePodAdded
	pod := &enrichment.PodInfo{
		Name:           "my-pod",
		Namespace:      "production",
		ServiceAccount: "my-sa",
		Labels: map[string]string{
			"app":       "my-app",
			"component": "frontend",
		},
		Containers: []string{"container-abc123"},
	}
	mgr.HandlePodAdded(pod)

	// Verify container info is enriched with pod metadata
	info := mgr.GetContainerInfo("container-abc123")
	if info == nil {
		t.Fatal("Expected container info to exist")
	}
	if info.PodName != "my-pod" {
		t.Errorf("Expected pod name 'my-pod', got %s", info.PodName)
	}
	if info.Namespace != "production" {
		t.Errorf("Expected namespace 'production', got %s", info.Namespace)
	}
	if info.ServiceAccount != "my-sa" {
		t.Errorf("Expected service account 'my-sa', got %s", info.ServiceAccount)
	}
	if info.Labels["app"] != "my-app" {
		t.Errorf("Expected label app=my-app, got %s", info.Labels["app"])
	}
}

func TestManager_PodEnrichment_UpdatesExistingLabels(t *testing.T) {
	mgr, _ := enrichment.NewManager(enrichment.ManagerConfig{
		ProcFSPath: "/proc",
	})

	// Register container with some labels
	containerInfo := &enrichment.ContainerInfo{
		ID:       "container-xyz789",
		Name:     "sidecar",
		Image:    "envoy:latest",
		CgroupID: 66666,
		Labels: map[string]string{
			"existing": "label",
		},
	}
	mgr.RegisterContainer(containerInfo)

	// Enrich with pod data
	pod := &enrichment.PodInfo{
		Name:           "sidecar-pod",
		Namespace:      "istio-system",
		ServiceAccount: "istio-sa",
		Labels: map[string]string{
			"app":  "envoy",
			"side": "car",
		},
		Containers: []string{"container-xyz789"},
	}
	mgr.HandlePodAdded(pod)

	info := mgr.GetContainerInfo("container-xyz789")
	if info == nil {
		t.Fatal("Expected container info to exist")
	}
	// Check that original labels are preserved AND pod labels are merged
	if info.Labels["existing"] != "label" {
		t.Error("Original label should be preserved")
	}
	if info.Labels["app"] != "envoy" {
		t.Error("Pod label should be merged")
	}
}

// ── K8s Integration Tests ──────────────────────────────────────────────

func TestNewK8sIntegration(t *testing.T) {
	k8s := enrichment.NewK8sIntegration("test-node")
	if k8s == nil {
		t.Fatal("Expected non-nil K8sIntegration")
	}
}

func TestK8sIntegration_EventsChannel(t *testing.T) {
	k8s := enrichment.NewK8sIntegration("test-node")
	ch := k8s.Events()
	if ch == nil {
		t.Error("Expected non-nil events channel")
	}
}

func TestK8sIntegration_Stats(t *testing.T) {
	k8s := enrichment.NewK8sIntegration("test-node")
	stats := k8s.Stats()
	if stats.NodeName != "test-node" {
		t.Errorf("Expected node name 'test-node', got %s", stats.NodeName)
	}
	if stats.Connected {
		t.Error("Should not be connected initially")
	}
}

func TestK8sIntegration_NotConnectedByDefault(t *testing.T) {
	k8s := enrichment.NewK8sIntegration("test-node")
	if k8s.IsConnected() {
		t.Error("K8s should not be connected by default")
	}
}

// ── K8s Cache Tests ────────────────────────────────────────────────────

func TestK8sCache_Basic(t *testing.T) {
	cache := enrichment.NewK8sCache("test-node")

	pod := &enrichment.PodInfo{
		Name:           "test-pod",
		Namespace:      "default",
		ServiceAccount: "default",
		Labels:         map[string]string{"app": "test"},
		Containers:     []string{"container-1", "container-2"},
	}

	// Set and Get
	cache.Set("default/test-pod", pod)

	retrieved := cache.Get("default/test-pod")
	if retrieved == nil {
		t.Fatal("Expected to retrieve pod")
	}
	if retrieved.Name != "test-pod" {
		t.Errorf("Expected pod name 'test-pod', got %s", retrieved.Name)
	}
	if len(retrieved.Containers) != 2 {
		t.Errorf("Expected 2 containers, got %d", len(retrieved.Containers))
	}

	// Size
	if cache.Size() != 1 {
		t.Errorf("Expected cache size 1, got %d", cache.Size())
	}

	// Delete
	cache.Delete("default/test-pod")
	if cache.Get("default/test-pod") != nil {
		t.Error("Expected nil after deletion")
	}
	if cache.Size() != 0 {
		t.Errorf("Expected cache size 0, got %d", cache.Size())
	}
}

func TestK8sCache_LookupByContainerID(t *testing.T) {
	cache := enrichment.NewK8sCache("test-node")

	pod := &enrichment.PodInfo{
		Name:           "test-pod",
		Namespace:      "production",
		ServiceAccount: "my-sa",
		Labels:         map[string]string{"app": "my-app"},
		Containers:     []string{"abc123", "def456"},
	}
	cache.Set("production/test-pod", pod)

	// Lookup by container ID
	result := cache.LookupByContainerID("abc123")
	if result == nil {
		t.Fatal("Expected to find pod by container ID")
	}
	if result.Name != "test-pod" {
		t.Errorf("Expected pod name 'test-pod', got %s", result.Name)
	}

	// Lookup nonexistent container
	result = cache.LookupByContainerID("nonexistent")
	if result != nil {
		t.Error("Expected nil for nonexistent container ID")
	}
}

// ── CRI Cache Tests ────────────────────────────────────────────────────

func TestCRICache_Basic(t *testing.T) {
	cache := enrichment.NewCRICache()

	info := &enrichment.ContainerInfo{
		ID:        "container-123",
		Name:      "nginx",
		Image:     "nginx:latest",
		Namespace: "default",
		CgroupID:  12345,
	}

	// Set and Get
	cache.Set("container-123", info)
	retrieved := cache.Get("container-123")
	if retrieved == nil {
		t.Fatal("Expected to retrieve container info")
	}
	if retrieved.Name != "nginx" {
		t.Errorf("Expected name 'nginx', got %s", retrieved.Name)
	}

	// Size
	if cache.Size() != 1 {
		t.Errorf("Expected size 1, got %d", cache.Size())
	}

	// Delete
	cache.Delete("container-123")
	if cache.Get("container-123") != nil {
		t.Error("Expected nil after deletion")
	}
	if cache.Size() != 0 {
		t.Errorf("Expected size 0, got %d", cache.Size())
	}
}

func TestCRICache_GetAllContainerIDs(t *testing.T) {
	cache := enrichment.NewCRICache()

	cache.Set("c1", &enrichment.ContainerInfo{ID: "c1"})
	cache.Set("c2", &enrichment.ContainerInfo{ID: "c2"})
	cache.Set("c3", &enrichment.ContainerInfo{ID: "c3"})

	ids := cache.GetAllContainerIDs()
	if len(ids) != 3 {
		t.Errorf("Expected 3 IDs, got %d", len(ids))
	}

	// Verify all IDs are present
	idSet := make(map[string]bool)
	for _, id := range ids {
		idSet[id] = true
	}
	if !idSet["c1"] || !idSet["c2"] || !idSet["c3"] {
		t.Error("Missing expected container IDs")
	}
}

// ── PID Cache Tests ────────────────────────────────────────────────────

func TestPIDCache_Basic(t *testing.T) {
	cache := enrichment.NewPIDCache(100, 5*time.Minute)

	// Set and Get
	cache.Set(1234, "container-abc")
	result := cache.Get(1234)
	if result != "container-abc" {
		t.Errorf("Expected 'container-abc', got %q", result)
	}

	// Get nonexistent
	result = cache.Get(9999)
	if result != "" {
		t.Errorf("Expected empty string for nonexistent PID, got %q", result)
	}
}

func TestPIDCache_Expiry(t *testing.T) {
	cache := enrichment.NewPIDCache(100, 100*time.Millisecond)

	cache.Set(1234, "container-abc")
	result := cache.Get(1234)
	if result != "container-abc" {
		t.Errorf("Expected 'container-abc', got %q", result)
	}

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)
	result = cache.Get(1234)
	if result != "" {
		t.Errorf("Expected empty string after TTL, got %q", result)
	}
}

// ── Container ID Extraction Tests ──────────────────────────────────────

func TestExtractContainerID_Containerd(t *testing.T) {
	cgroupData := "0::/system.slice/containerd.service/abc123def456789012345678901234567890abcdef1234567890abcdef12345678\n"
	id := enrichment.ExtractContainerID(cgroupData)
	if id == "" {
		t.Error("Expected to extract container ID from containerd cgroup")
	}
}

func TestExtractContainerID_Docker(t *testing.T) {
	cgroupData := "0::/docker/abc123def456789012345678901234567890abcdef1234567890abcdef12345678\n"
	id := enrichment.ExtractContainerID(cgroupData)
	if id == "" {
		t.Error("Expected to extract container ID from Docker cgroup")
	}
}

func TestExtractContainerID_Empty(t *testing.T) {
	id := enrichment.ExtractContainerID("")
	if id != "" {
		t.Errorf("Expected empty string for empty cgroup data, got %q", id)
	}
}

func TestExtractContainerIDFromPodStatus(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"containerd://abc123def456", "abc123def456"},
		{"cri-o://789ghi012jkl", "789ghi012jkl"},
		{"docker://345mno678pqr", "345mno678pqr"},
		{"abc123", "abc123"}, // No prefix
		{"", ""},               // Empty
	}

	for _, tc := range tests {
		result := enrichment.ExtractContainerIDFromPodStatus(tc.input)
		if result != tc.expected {
			t.Errorf("ExtractContainerIDFromPodStatus(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

// ── Manager Concurrent Registration Tests ──────────────────────────────

func TestManager_ConcurrentRegistration(t *testing.T) {
	mgr, _ := enrichment.NewManager(enrichment.ManagerConfig{
		ProcFSPath: "/proc",
	})

	// Concurrently register multiple containers
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			info := &enrichment.ContainerInfo{
				ID:       fmt.Sprintf("concurrent-%d", idx),
				Name:     fmt.Sprintf("container-%d", idx),
				CgroupID: uint64(10000 + idx),
			}
			mgr.RegisterContainer(info)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	if mgr.ContainerCount() != 10 {
		t.Errorf("Expected 10 containers, got %d", mgr.ContainerCount())
	}
}

// ── CRI Event Tests ──────────────────────────────────────────────────

func TestCRIEvent_TypeValues(t *testing.T) {
	containerInfo := &enrichment.ContainerInfo{
		ID:   "test-container-event",
		Name: "test-event-container",
	}

	evt := enrichment.CRIEvent{
		Type:      enrichment.CRIEventContainerStart,
		Container: containerInfo,
		Timestamp: time.Now(),
	}

	if evt.Type != enrichment.CRIEventContainerStart {
		t.Errorf("Expected container_start, got %s", evt.Type)
	}
	if evt.Container.ID != "test-container-event" {
		t.Errorf("Expected container ID 'test-container-event', got %s", evt.Container.ID)
	}
}

// ── K8s Event Tests ──────────────────────────────────────────────────

func TestK8sEvent_TypeValues(t *testing.T) {
	podInfo := &enrichment.PodInfo{
		Name:      "test-pod-event",
		Namespace: "default",
	}

	evt := enrichment.K8sEvent{
		Type:      enrichment.K8sEventPodAdded,
		Pod:       podInfo,
		Timestamp: time.Now(),
	}

	if evt.Type != enrichment.K8sEventPodAdded {
		t.Errorf("Expected pod_added, got %s", evt.Type)
	}
	if evt.Pod.Name != "test-pod-event" {
		t.Errorf("Expected pod name 'test-pod-event', got %s", evt.Pod.Name)
	}
}

// ── Pod Info Tests ──────────────────────────────────────────────────────

func TestPodInfo_Fields(t *testing.T) {
	pod := &enrichment.PodInfo{
		Name:           "my-app-pod",
		Namespace:      "production",
		ServiceAccount: "my-sa",
		Labels: map[string]string{
			"app":       "my-app",
			"version":   "v2",
			"component": "api",
		},
		Containers: []string{"c1", "c2", "c3"},
	}

	if pod.Name != "my-app-pod" {
		t.Errorf("Expected name 'my-app-pod', got %s", pod.Name)
	}
	if pod.Namespace != "production" {
		t.Errorf("Expected namespace 'production', got %s", pod.Namespace)
	}
	if pod.ServiceAccount != "my-sa" {
		t.Errorf("Expected SA 'my-sa', got %s", pod.ServiceAccount)
	}
	if len(pod.Containers) != 3 {
		t.Errorf("Expected 3 containers, got %d", len(pod.Containers))
	}
	if pod.Labels["app"] != "my-app" {
		t.Errorf("Expected label app=my-app, got %s", pod.Labels["app"])
	}
}

// ── CRI Disconnect Test ────────────────────────────────────────────────

func TestCRIIntegration_Disconnect(t *testing.T) {
	cri := enrichment.NewCRIIntegration("/run/containerd/containerd.sock")
	cri.Disconnect() // Should not panic even if never connected
	if cri.IsConnected() {
		t.Error("Should not be connected after disconnect")
	}
}

// ── CRIStats Test ──────────────────────────────────────────────────────

func TestCRIIntegration_StatsAfterConnectAttempt(t *testing.T) {
	cri := enrichment.NewCRIIntegration("/nonexistent.sock")
	_ = cri.Connect() // Should fail but not panic

	stats := cri.Stats()
	if stats.ConnectAttempts < 1 {
		t.Errorf("Expected at least 1 connect attempt, got %d", stats.ConnectAttempts)
	}
	if stats.LastError == "" {
		t.Error("Expected last error to be set after failed connect")
	}
}