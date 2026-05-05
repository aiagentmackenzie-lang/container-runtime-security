// Package ebpf provides eBPF program loading, event type definitions,
// and ring buffer reading for the SecurityScarlet Runtime agent.
package ebpf

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ── Event Category Constants ──────────────────────────────────────────

const (
	CatProcess    uint8 = 1
	CatFile       uint8 = 2
	CatNetwork    uint8 = 3
	CatEscape     uint8 = 4
	CatPrivilege  uint8 = 5
	CatCredential uint8 = 6
)

// CategoryName maps category byte to human-readable name.
var CategoryName = map[uint8]string{
	CatProcess:    "PROCESS",
	CatFile:       "FILE",
	CatNetwork:    "NETWORK",
	CatEscape:     "ESCAPE",
	CatPrivilege:  "PRIVILEGE",
	CatCredential: "CREDENTIAL",
}

// ── Event Type Constants ──────────────────────────────────────────────

const (
	// Process events
	EvtExec uint8 = 1
	EvtFork uint8 = 2
	EvtExit uint8 = 3

	// File events
	EvtFileOpen  uint8 = 10
	EvtFileUnlink uint8 = 11
	EvtFileMemfd uint8 = 12
	EvtFileRename uint8 = 13

	// Network events
	EvtNetConnect uint8 = 20
	EvtNetListen  uint8 = 21
	EvtNetState   uint8 = 22
	EvtNetUDP     uint8 = 23

	// Escape events
	EvtSetns       uint8 = 30
	EvtUnshare     uint8 = 31
	EvtMount       uint8 = 32
	EvtPtrace      uint8 = 33
	EvtModuleLoad  uint8 = 34
	EvtBpfLoad     uint8 = 35

	// Privilege events
	EvtSetuid      uint8 = 40
	EvtSetresuid   uint8 = 41
	EvtCapset      uint8 = 42
	EvtChmod       uint8 = 43

	// Credential events
	EvtCredAccess  uint8 = 50
)

// EventTypeName maps event type byte to human-readable name.
var EventTypeName = map[uint8]string{
	EvtExec:        "EXEC",
	EvtFork:        "FORK",
	EvtExit:        "EXIT",
	EvtFileOpen:    "FILE_OPEN",
	EvtFileUnlink:  "FILE_UNLINK",
	EvtFileMemfd:   "FILE_MEMFD",
	EvtFileRename:  "FILE_RENAME",
	EvtNetConnect:  "NET_CONNECT",
	EvtNetListen:   "NET_LISTEN",
	EvtNetState:    "NET_STATE",
	EvtNetUDP:      "NET_UDP",
	EvtSetns:       "SETNS",
	EvtUnshare:     "UNSHARE",
	EvtMount:       "MOUNT",
	EvtPtrace:      "PTRACE",
	EvtModuleLoad:  "MODULE_LOAD",
	EvtBpfLoad:     "BPF_LOAD",
	EvtSetuid:      "SETUID",
	EvtSetresuid:   "SETRESUID",
	EvtCapset:      "CAPSET",
	EvtChmod:       "CHMOD",
	EvtCredAccess:  "CRED_ACCESS",
}

// ── Struct sizes (must match C header) ────────────────────────────────

const (
	MaxCommLen  = 16
	MaxPathLen  = 256
	MaxArgsLen  = 128
	MaxIPv4Addr = 4
	NSCount     = 8
)

// ScarletEvent is the Go representation of struct scarlet_event from the
// eBPF C header. This is the primary data structure that flows through
// the event processing pipeline.
type ScarletEvent struct {
	// Header fields (common to all events)
	TimestampNS uint64
	PID         uint32
	TGID        uint32
	PPID        uint32
	UID         uint32
	GID         uint32
	CgroupID    uint64
	PIDNSLevel  uint32
	Category    uint8
	EventType   uint8
	SyscallNr   uint16
	_           [2]byte // padding
	Comm        [MaxCommLen]byte

	// Payload union — all payloads are present but only one is valid
	// based on the Category field
	Payload EventPayload
}

// EventPayload holds the category-specific data. All sub-structs are
// present; the consumer must check Category to know which is valid.
type EventPayload struct {
	Process  ProcessPayload
	File     FilePayload
	Network  NetworkPayload
	Escape   EscapePayload
	Privilege PrivilegePayload
}

// ProcessPayload holds data for SCARLET_CAT_PROCESS events.
type ProcessPayload struct {
	Filename [MaxPathLen]byte
	Args     [MaxArgsLen]byte
}

// FilePayload holds data for SCARLET_CAT_FILE events.
type FilePayload struct {
	Path  [MaxPathLen]byte
	Flags uint32
	Mode  uint32
}

// NetworkPayload holds data for SCARLET_CAT_NETWORK events.
type NetworkPayload struct {
	LocalAddr  [MaxIPv4Addr]byte
	RemoteAddr [MaxIPv4Addr]byte
	LocalPort  uint16
	RemotePort uint16
	Protocol   uint8
	Family     uint8
	_          uint16 // padding
}

// EscapePayload holds data for SCARLET_CAT_ESCAPE events.
type EscapePayload struct {
	NSType    uint32
	TargetNS  [NSCount]uint32
	NSCount   uint8
	_         [3]byte // padding
}

// PrivilegePayload holds data for SCARLET_CAT_PRIVILEGE events.
type PrivilegePayload struct {
	OldUID    uint32
	NewUID    uint32
	Capability uint32
	ModeFlags uint32
}

// ── Helper methods ────────────────────────────────────────────────────

// CategoryString returns the human-readable category name.
func (e *ScarletEvent) CategoryString() string {
	if name, ok := CategoryName[e.Category]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", e.Category)
}

// EventTypeString returns the human-readable event type name.
func (e *ScarletEvent) EventTypeString() string {
	if name, ok := EventTypeName[e.EventType]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", e.EventType)
}

// CommString returns the process command name as a Go string.
func (e *ScarletEvent) CommString() string {
	return nullTerminatedString(e.Comm[:])
}

// Filename returns the process filename (valid for PROCESS events).
func (e *ScarletEvent) Filename() string {
	return nullTerminatedString(e.Payload.Process.Filename[:])
}

// Args returns the process arguments (valid for PROCESS events).
func (e *ScarletEvent) Args() string {
	return nullTerminatedString(e.Payload.Process.Args[:])
}

// FilePath returns the file path (valid for FILE events).
func (e *ScarletEvent) FilePath() string {
	return nullTerminatedString(e.Payload.File.Path[:])
}

// RemoteIP returns the remote IP address as a dotted-quad string (valid for NETWORK events).
func (e *ScarletEvent) RemoteIP() string {
	addr := e.Payload.Network.RemoteAddr
	return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
}

// LocalIP returns the local IP address as a dotted-quad string.
func (e *ScarletEvent) LocalIP() string {
	addr := e.Payload.Network.LocalAddr
	return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
}

// RemotePort returns the remote port in host byte order.
func (e *ScarletEvent) RemotePort() uint16 {
	return e.Payload.Network.RemotePort
}

// LocalPort returns the local port.
func (e *ScarletEvent) LocalPort() uint16 {
	return e.Payload.Network.LocalPort
}

// IsContainer returns true if the event originated from a container process.
func (e *ScarletEvent) IsContainer() bool {
	return e.PIDNSLevel > 0
}

// IsHost returns true if the event originated from a host process.
func (e *ScarletEvent) IsHost() bool {
	return e.PIDNSLevel == 0
}

// IsSensitivePath checks if a file path matches known sensitive paths.
func (e *ScarletEvent) IsSensitivePath() bool {
	if e.Category != CatFile {
		return false
	}
	path := e.FilePath()
	return IsSensitivePath(path)
}

// ── Sensitive paths ───────────────────────────────────────────────────

// SensitivePaths is the list of paths considered sensitive for security monitoring.
var SensitivePaths = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	"/root/.ssh",
	"/root/.ssh/",
	"/var/run/docker.sock",
	"/proc/1/ns",
	"/proc/1/environ",
	"/proc/1/maps",
	"/proc/kallsyms",
	"/proc/self/exe",
	"/proc/self/fd",
	"/var/run/secrets/kubernetes.io/",
}

// IsSensitivePath checks if a path starts with any known sensitive prefix.
func IsSensitivePath(path string) bool {
	for _, prefix := range SensitivePaths {
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// ── Known mining pool ports ──────────────────────────────────────────

// MinerPoolPorts contains known cryptocurrency mining pool ports.
var MinerPoolPorts = map[uint16]bool{
	25: true, 3333: true, 3334: true, 3335: true, 3336: true,
	3357: true, 4444: true, 5555: true, 5556: true, 5588: true,
	5730: true, 6099: true, 6666: true, 7777: true, 7778: true,
	8333: true, 8888: true, 8899: true, 9332: true, 9999: true,
	14433: true, 14444: true, 45560: true, 45700: true,
}

// IsMinerPoolPort checks if a port is a known mining pool port.
func IsMinerPoolPort(port uint16) bool {
	return MinerPoolPorts[port]
}

// ── Known C2 ports ───────────────────────────────────────────────────

// C2Ports contains common command-and-control ports.
var C2Ports = map[uint16]bool{
	4444: true, 1337: true, 31337: true, 6666: true,
	8080: true, 9001: true, 1234: true, 4443: true,
}

// IsC2Port checks if a port is a known C2 port.
func IsC2Port(port uint16) bool {
	return C2Ports[port]
}

// ── Cloud metadata IPs ──────────────────────────────────────────────

// CloudMetadataIPs contains known cloud metadata service IPs.
var CloudMetadataIPs = map[string]bool{
	"169.254.169.254": true, // AWS/GCP/Azure
	"168.63.129.16":   true, // Azure
}

// IsCloudMetadataIP checks if an IP is a known cloud metadata service.
func IsCloudMetadataIP(ip string) bool {
	return CloudMetadataIPs[ip]
}

// ── Shell binaries ──────────────────────────────────────────────────

// ShellBinaries contains known shell binary names.
var ShellBinaries = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true,
	"ksh": true, "tcsh": true, "fish": true, "csh": true,
}

// IsShellProcess checks if a command name is a known shell binary.
func IsShellProcess(comm string) bool {
	return ShellBinaries[comm]
}

// ── Miner binaries ───────────────────────────────────────────────────

// MinerBinaries contains known cryptominer binary names.
var MinerBinaries = map[string]bool{
	"xmrig": true, "ccminer": true, "t-rex": true,
	"nanominer": true, "pwnrig": true, "minerd": true,
	"xmr-stak": true, "cpuminer": true, "cgminer": true,
	"bfgminer": true, "claymore": true, "ethminer": true,
	"phoenixminer": true, "nbminer": true, "lolMiner": true,
}

// IsMinerProcess checks if a command name is a known miner binary.
func IsMinerProcess(comm string) bool {
	return MinerBinaries[comm]
}

// ── Binary decoding ──────────────────────────────────────────────────

// EventStructSize is the size of the C scarlet_event struct.
// Must match exactly with the C header layout.
const EventStructSize = 432 // approximate; see C struct for exact layout

// DecodeEvent decodes a raw byte slice from the ring buffer into a ScarletEvent.
// The byte layout must match the packed struct from security_scarlet_event.h.
func DecodeEvent(data []byte) (*ScarletEvent, error) {
	if len(data) < 64 { // minimum meaningful event
		return nil, fmt.Errorf("event data too short: %d bytes", len(data))
	}

	e := &ScarletEvent{}
	offset := 0

	// Fixed header fields
	e.TimestampNS = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	e.PID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	e.TGID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	e.PPID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	e.UID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	e.GID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	e.CgroupID = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	e.PIDNSLevel = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	e.Category = data[offset]
	offset += 1

	e.EventType = data[offset]
	offset += 1

	e.SyscallNr = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 2 bytes padding
	offset += 2

	// Comm[16]
	copy(e.Comm[:], data[offset:offset+MaxCommLen])
	offset += MaxCommLen

	// Payload union — read based on category
	switch e.Category {
	case CatProcess:
		if offset+MaxPathLen+MaxArgsLen <= len(data) {
			copy(e.Payload.Process.Filename[:], data[offset:offset+MaxPathLen])
			offset += MaxPathLen
			copy(e.Payload.Process.Args[:], data[offset:offset+MaxArgsLen])
		}
	case CatFile:
		if offset+MaxPathLen+4+4 <= len(data) {
			copy(e.Payload.File.Path[:], data[offset:offset+MaxPathLen])
			offset += MaxPathLen
			e.Payload.File.Flags = binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
			e.Payload.File.Mode = binary.LittleEndian.Uint32(data[offset : offset+4])
		}
	case CatNetwork:
		if offset+4+4+2+2+1+1+2 <= len(data) {
			copy(e.Payload.Network.LocalAddr[:], data[offset:offset+4])
			offset += 4
			copy(e.Payload.Network.RemoteAddr[:], data[offset:offset+4])
			offset += 4
			e.Payload.Network.LocalPort = binary.LittleEndian.Uint16(data[offset : offset+2])
			offset += 2
			e.Payload.Network.RemotePort = binary.LittleEndian.Uint16(data[offset : offset+2])
			offset += 2
			e.Payload.Network.Protocol = data[offset]
			offset += 1
			e.Payload.Network.Family = data[offset]
			offset += 1
			// 2 bytes padding
		}
	case CatEscape:
		if offset+4+NSCount*4+1+3 <= len(data) {
			e.Payload.Escape.NSType = binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
			for i := 0; i < NSCount; i++ {
				e.Payload.Escape.TargetNS[i] = binary.LittleEndian.Uint32(data[offset : offset+4])
				offset += 4
			}
			e.Payload.Escape.NSCount = data[offset]
		}
	case CatPrivilege:
		if offset+4*4 <= len(data) {
			e.Payload.Privilege.OldUID = binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
			e.Payload.Privilege.NewUID = binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
			e.Payload.Privilege.Capability = binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
			e.Payload.Privilege.ModeFlags = binary.LittleEndian.Uint32(data[offset : offset+4])
		}
	}

	return e, nil
}

// ── Internal helpers ──────────────────────────────────────────────────

func nullTerminatedString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// SizeofScarletEvent returns the size of the C scarlet_event struct.
// Hardcoded to 432 bytes per the C header layout (security_scarlet_event.h).
// This avoids CGO dependency for a pure-Go agent build.
func SizeofScarletEvent() uintptr {
	return uintptr(EventStructSize)
}

// ── TLS ClientHello SNI Extraction ──────────────────────────────────────
//
// These functions extract the Server Name Indication (SNI) from TLS
// ClientHello messages observed in network events. The eBPF TC classifier
// can capture the first bytes of TCP connections, and these functions parse
// the TLS handshake to find the SNI extension.
//
// TLS ClientHello format (RFC 5246 §7.4.1.2):
//   - ContentType: 22 (Handshake)
//   - Version: 2 bytes (TLS 1.0+)
//   - Length: 2 bytes
//   - HandshakeType: 1 (ClientHello)
//   - HandshakeLength: 3 bytes
//   - ClientVersion: 2 bytes
//   - Random: 32 bytes
//   - SessionID: 1-byte length + variable
//   - CipherSuites: 2-byte length + variable
//   - CompressionMethods: 1-byte length + variable
//   - Extensions: 2-byte length + variable
//     - SNI Extension (type=0): 2-byte list length + list entries
//       - Entry: 1-byte type (0=hostname) + 2-byte length + hostname

const (
	TLSContentTypeHandshake = 22
	TLSHandshakeTypeClientHello = 1
	TLSExtensionServerName = 0
	TLSExtensionSNIHostName = 0
)

// TLSSNIResult holds the result of TLS SNI extraction.
type TLSSNIResult struct {
	SNI           string    // Extracted Server Name Indication
	TLSVersion    uint16    // TLS version from the ClientHello
	HasSNI        bool      // Whether SNI was found
	IsSuspicious  bool      // Whether the SNI is considered suspicious
	SuspiciousReasons []string // Reasons the SNI is suspicious
}

// ExtractTLSClientHelloSNI parses a TLS ClientHello from raw network payload
// bytes and extracts the SNI extension value. Returns a TLSSNIResult
// with the extracted SNI and metadata.
//
// The payload should start at the beginning of the TLS record layer.
func ExtractTLSClientHelloSNI(payload []byte) *TLSSNIResult {
	result := &TLSSNIResult{}

	// Minimum TLS record header: 5 bytes (ContentType + Version + Length)
	if len(payload) < 5 {
		return result
	}

	// Check ContentType (must be Handshake = 22)
	if payload[0] != TLSContentTypeHandshake {
		return result
	}

	// Extract TLS version
	result.TLSVersion = binary.BigEndian.Uint16(payload[1:3])

	// TLS record length
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recordLen+5 > len(payload) {
		// Truncated — use what we have
		recordLen = len(payload) - 5
	}

	// Handshake header: 1 byte type + 3 bytes length
	handshakeOffset := 5
	if handshakeOffset+4 > len(payload) {
		return result
	}

	// Check HandshakeType (must be ClientHello = 1)
	if payload[handshakeOffset] != TLSHandshakeTypeClientHello {
		return result
	}

	// Handshake length (3 bytes, big-endian)
	handshakeLen := int(payload[handshakeOffset+1])<<16 |
		int(payload[handshakeOffset+2])<<8 |
		int(payload[handshakeOffset+3])

	// Use handshakeLen for bounds checking
	remaining := min(handshakeLen+4, len(payload)-5)
	_ = remaining

	// ClientHello body starts after handshake header
	offset := handshakeOffset + 4

	// ClientVersion (2 bytes)
	if offset+2 > len(payload) {
		return result
	}
	_ = binary.BigEndian.Uint16(payload[offset : offset+2]) // clientVersion
	offset += 2

	// Random (32 bytes)
	if offset+32 > len(payload) {
		return result
	}
	offset += 32 // skip Random

	// Session ID (1-byte length + variable)
	if offset+1 > len(payload) {
		return result
	}
	sessionIDLen := int(payload[offset])
	offset += 1
	if offset+sessionIDLen > len(payload) {
		return result
	}
	offset += sessionIDLen

	// CipherSuites (2-byte length + variable)
	if offset+2 > len(payload) {
		return result
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	if offset+cipherSuitesLen > len(payload) {
		// Truncated, but try to continue with what we have
		cipherSuitesLen = min(cipherSuitesLen, len(payload)-offset)
	}
	offset += cipherSuitesLen

	// Compression methods (1-byte length + variable)
	if offset+1 > len(payload) {
		return result
	}
	compressionLen := int(payload[offset])
	offset += 1
	if offset+compressionLen > len(payload) {
		return result
	}
	offset += compressionLen

	// Extensions length (2 bytes)
	if offset+2 > len(payload) {
		return result
	}
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	if extensionsLen == 0 {
		return result
	}

	// Adjust extensionsLen to available data
	extEnd := offset + extensionsLen
	if extEnd > len(payload) {
		extEnd = len(payload)
	}

	// Parse extensions
	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extDataLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		if offset+extDataLen > extEnd {
			break
		}

		if extType == TLSExtensionServerName {
			 sni := parseSNIExtension(payload[offset : offset+extDataLen])
			 if sni != "" {
				 result.SNI = sni
				 result.HasSNI = true

				// Check for suspicious SNI
				 reasons := CheckSuspiciousSNI(sni)
				 if len(reasons) > 0 {
					 result.IsSuspicious = true
					 result.SuspiciousReasons = reasons
				 }

				 return result
			 }
		}

		offset += extDataLen
	}

	return result
}

// parseSNIExtension parses an SNI extension payload and returns the hostname.
func parseSNIExtension(data []byte) string {
	// SNI Extension format:
	//   - 2-byte: Server Name List Length
	//   - Server Name List:
	//     - 1-byte: Name Type (0 = hostname)
	//     - 2-byte: Name Length
	//     - Name bytes

	if len(data) < 2 {
		return ""
	}

	// Server Name List Length
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen > len(data)-2 {
		listLen = len(data) - 2
	}

	offset := 2
	for offset+3 <= len(data) {
		nameType := data[offset]
		nameLen := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		offset += 3

		if nameType == TLSExtensionSNIHostName && offset+nameLen <= len(data) {
			return string(data[offset : offset+nameLen])
		}

		offset += nameLen
	}

	return ""
}

// ── Suspicious SNI Detection ────────────────────────────────────────

// SNISuspiciousPatterns contains patterns for detecting suspicious TLS SNI values.
var SNISuspiciousPatterns = []struct {
	Name        string
	Description string
	Check       func(sni string) bool
}{
	{
		Name:        "mining_pool_domain",
		Description: "SNI matches known cryptocurrency mining pool pattern",
		Check:       isSNIMiningPool,
	},
	{
		Name:        "suspicious_tld",
		Description: "SNI uses a suspicious TLD often associated with malware",
		Check:       isSNISuspiciousTLD,
	},
	{
		Name:        "long_random_subdomain",
		Description: "SNI has an unusually long or random-looking subdomain",
		Check:       isSNILongRandom,
	},
	{
	Name:        "tor_hidden_service",
		Description: "SNI appears to be a Tor .onion address",
		Check:       isSNITorHiddenService,
	},
	{
		Name:        "ip_address_sni",
		Description: "SNI contains an IP address instead of a hostname",
		Check:       isSNIIPAddress,
	},
}

// CheckSuspiciousSNI examines an SNI hostname for suspicious patterns
// and returns a list of matching pattern names.
func CheckSuspiciousSNI(sni string) []string {
	var reasons []string
	for _, pattern := range SNISuspiciousPatterns {
		if pattern.Check(sni) {
			reasons = append(reasons, pattern.Name)
		}
	}
	return reasons
}

// isSNIMiningPool checks if the SNI matches known mining pool domain patterns.
func isSNIMiningPool(sni string) bool {
	lower := strings.ToLower(sni)
	miningPatterns := []string{
		"miningpoolhub",
		"nanopool",
		"ethermine",
		"f2pool",
		"antpool",
		"slushpool",
		"nicehash",
		"minergate",
		"coinhive",
		"cryptoloot",
		"hashflare",
		"genesis-mining",
		"stratum",
		"xmrpool",
		"dwarfpool",
	}
	for _, p := range miningPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// isSNISuspiciousTLD checks if the SNI uses a suspicious TLD.
func isSNISuspiciousTLD(sni string) bool {
	suspicious := []string{".tk", ".ml", ".ga", ".cf", ".gq", ".bid", ".click", ".download"}
	for _, tld := range suspicious {
		if strings.HasSuffix(strings.ToLower(sni), tld) {
			return true
		}
	}
	return false
}

// isSNILongRandom checks if the SNI has an unusually long or random subdomain.
func isSNILongRandom(sni string) bool {
	parts := strings.Split(sni, ".")
	if len(parts) < 2 {
		return false
	}
	// First label (subdomain) that is very long and looks random
	label := parts[0]
	if len(label) >= 20 {
		return true
	}
	return false
}

// isSNITorHiddenService checks if the SNI is a Tor .onion address.
func isSNITorHiddenService(sni string) bool {
	return strings.HasSuffix(strings.ToLower(sni), ".onion")
}

// isSNIIPAddress checks if the SNI contains an IP address pattern.
func isSNIIPAddress(sni string) bool {
	// Simple check: does the SNI look like an IP address?
	// IP-based SNIs are suspicious because real TLS certs use hostnames
	parts := strings.Split(sni, ".")
	if len(parts) == 4 {
		digitCount := 0
		for _, p := range parts {
			for _, c := range p {
				if c >= '0' && c <= '9' {
					digitCount++
				}
			}
		}
		// If most characters are digits, it's likely an IP address
		if digitCount >= len(sni)-3 { // Allow for dots
			return true
		}
	}
	return false
}

// IsDNSPort checks if a port is the standard DNS port.
func IsDNSPort(port uint16) bool {
	return port == DNSPort
}