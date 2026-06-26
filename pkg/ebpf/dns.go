// Package ebpf - dns.go
// DNS query/answer parsing from wire format (RFC 1035).
//
// This module provides UDP port 53 payload parsing for eBPF network events.
// The eBPF network probe captures UDP packets to/from port 53, and this
// module extracts DNS question/answer records for monitoring.
//
// DNS message format (RFC 1035):
//   Header: 12 bytes (ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
//   Questions: QDCOUNT × (NAME + TYPE + CLASS)
//   Answers: ANCOUNT × (NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA)
//
// This implementation supports:
//   - Standard DNS query parsing (type A, AAAA, CNAME, MX, TXT, etc.)
//   - DNS response parsing with answer records
//   - Label decompression (RFC 1035 §4.1.4)
//   - Suspicious query detection (DGAs, tunnel indicators, etc.)

package ebpf

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ── DNS Constants ─────────────────────────────────────────────────────

const (
	// DNS port
	DNSPort uint16 = 53

	// DNS header size (bytes)
	DNSHeaderSize = 12

	// DNS record types
	DNSTypeA     uint16 = 1
	DNSTypeNS    uint16 = 2
	DNSTypeCNAME uint16 = 5
	DNSTypeSOA   uint16 = 6
	DNSTypePTR   uint16 = 12
	DNSTypeMX    uint16 = 15
	DNSTypeTXT   uint16 = 16
	DNSTypeAAAA  uint16 = 28
	DNSTypeSRV   uint16 = 33
	DNSTypeANY   uint16 = 255

	// DNS response codes
	DNSRcodeNoError  uint8 = 0
	DNSRcodeFormErr  uint8 = 1
	DNSRcodeServFail uint8 = 2
	DNSRcodeNXDomain uint8 = 3
	DNSRcodeRefused  uint8 = 5

	// DNS flags
	DNSFlagQR uint16 = 0x8000 // Query/Response bit
	DNSFlagAA uint16 = 0x0400 // Authoritative Answer
	DNSFlagTC uint16 = 0x0200 // Truncation
	DNSFlagRD uint16 = 0x0100 // Recursion Desired
	DNSFlagRA uint16 = 0x0080 // Recursion Available
	DNSFlagAD uint16 = 0x0020 // Authenticated Data
	DNSFlagCD uint16 = 0x0010 // Checking Disabled
)

// ── DNS Types ─────────────────────────────────────────────────────────

// DNSHeader represents the fixed-size header of a DNS message.
type DNSHeader struct {
	ID      uint16 // Transaction ID
	Flags   uint16 // Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
	QDCount uint16 // Number of questions
	ANCount uint16 // Number of answers
	NSCount uint16 // Number of authority records
	ARCount uint16 // Number of additional records
}

// DNSQuestion represents a single DNS question record.
type DNSQuestion struct {
	Name  string // Domain name (e.g., "example.com.")
	Type  uint16 // Record type (A, AAAA, CNAME, etc.)
	Class uint16 // Record class (IN=1)
}

// DNSAnswer represents a single DNS answer/resource record.
type DNSAnswer struct {
	Name     string // Domain name
	Type     uint16 // Record type
	Class    uint16 // Record class
	TTL      uint32 // Time-to-live
	RDLength uint16 // RDATA length
	RData    string // RDATA as string (IP address for A/AAAA, domain for CNAME, etc.)
}

// DNSMessage represents a parsed DNS message.
type DNSMessage struct {
	Header    DNSHeader
	Questions []DNSQuestion
	Answers   []DNSAnswer
	Raw       []byte // Original raw data
}

// IsQuery returns true if this is a DNS query (QR bit = 0).
func (m *DNSMessage) IsQuery() bool {
	return m.Header.Flags&DNSFlagQR == 0
}

// IsResponse returns true if this is a DNS response (QR bit = 1).
func (m *DNSMessage) IsResponse() bool {
	return m.Header.Flags&DNSFlagQR != 0
}

// Rcode returns the DNS response code.
func (m *DNSMessage) Rcode() uint8 {
	return uint8(m.Header.Flags & 0x000F)
}

// OpCode returns the DNS opcode.
func (m *DNSMessage) OpCode() uint8 {
	return uint8((m.Header.Flags >> 11) & 0x0F)
}

// Truncated returns true if the TC (truncation) bit is set.
func (m *DNSMessage) Truncated() bool {
	return m.Header.Flags&DNSFlagTC != 0
}

// ── DNS Parsing ───────────────────────────────────────────────────────

// ParseDNSMessage parses a DNS message from raw bytes.
// Returns the parsed message, or an error if the data is too short or invalid.
func ParseDNSMessage(data []byte) (*DNSMessage, error) {
	if len(data) < DNSHeaderSize {
		return nil, fmt.Errorf("DNS data too short: %d bytes (need at least %d)", len(data), DNSHeaderSize)
	}

	msg := &DNSMessage{
		Raw: data,
	}

	// Parse header
	msg.Header.ID = binary.BigEndian.Uint16(data[0:2])
	msg.Header.Flags = binary.BigEndian.Uint16(data[2:4])
	msg.Header.QDCount = binary.BigEndian.Uint16(data[4:6])
	msg.Header.ANCount = binary.BigEndian.Uint16(data[6:8])
	msg.Header.NSCount = binary.BigEndian.Uint16(data[8:10])
	msg.Header.ARCount = binary.BigEndian.Uint16(data[10:12])

	offset := DNSHeaderSize

	// Parse questions
	for i := uint16(0); i < msg.Header.QDCount; i++ {
		name, newOffset, err := parseDNSName(data, offset)
		if err != nil {
			return msg, fmt.Errorf("error parsing question %d name: %w", i, err)
		}
		offset = newOffset

		if offset+4 > len(data) {
			return msg, fmt.Errorf("DNS data truncated in question %d", i)
		}

		qtype := binary.BigEndian.Uint16(data[offset : offset+2])
		qclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		msg.Questions = append(msg.Questions, DNSQuestion{
			Name:  name,
			Type:  qtype,
			Class: qclass,
		})
	}

	// Parse answers
	for i := uint16(0); i < msg.Header.ANCount; i++ {
		answer, newOffset, err := parseDNSAnswer(data, offset)
		if err != nil {
			// Return what we have so far rather than failing completely
			return msg, nil
		}
		offset = newOffset
		msg.Answers = append(msg.Answers, answer)
	}

	return msg, nil
}

// parseDNSName parses a DNS domain name from wire format, handling
// label compression (RFC 1035 §4.1.4).
func parseDNSName(data []byte, offset int) (string, int, error) {
	var labels []string
	jumped := false
	jumpFrom := -1
	visited := make(map[int]bool) // compression loop detection

	for {
		if offset >= len(data) {
			return strings.Join(labels, "."), offset, fmt.Errorf("DNS name offset beyond data")
		}

		// Check for compression loop
		if visited[offset] {
			return strings.Join(labels, "."), offset, fmt.Errorf("DNS compression loop detected")
		}
		visited[offset] = true

		length := int(data[offset])
		offset++

		if length == 0 {
			// End of name
			break
		}

		if length&0xC0 == 0xC0 {
			// Compression pointer
			if offset >= len(data) {
				return strings.Join(labels, "."), offset, fmt.Errorf("DNS compression pointer beyond data")
			}

			pointer := int(length&0x3F)<<8 | int(data[offset])
			offset++

			if !jumped {
				jumpFrom = offset
				jumped = true
			}

			// Follow pointer
			offset = pointer
			continue
		}

		if length > 63 {
			return strings.Join(labels, "."), offset, fmt.Errorf("DNS label too long: %d", length)
		}

		if offset+length > len(data) {
			return strings.Join(labels, "."), offset, fmt.Errorf("DNS label beyond data: offset=%d length=%d dataLen=%d", offset, length, len(data))
		}

		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}

	if jumped && jumpFrom >= 0 {
		return strings.Join(labels, "."), jumpFrom, nil
	}

	return strings.Join(labels, "."), offset, nil
}

// parseDNSAnswer parses a single DNS answer/resource record.
func parseDNSAnswer(data []byte, offset int) (DNSAnswer, int, error) {
	var answer DNSAnswer

	// Parse name (may use compression)
	name, newOffset, err := parseDNSName(data, offset)
	if err != nil {
		return answer, offset, fmt.Errorf("error parsing answer name: %w", err)
	}
	answer.Name = name
	offset = newOffset

	if offset+10 > len(data) {
		return answer, offset, fmt.Errorf("DNS answer header beyond data")
	}

	answer.Type = binary.BigEndian.Uint16(data[offset : offset+2])
	answer.Class = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	answer.TTL = binary.BigEndian.Uint32(data[offset+4 : offset+8])
	answer.RDLength = binary.BigEndian.Uint16(data[offset+8 : offset+10])
	offset += 10

	if offset+int(answer.RDLength) > len(data) {
		// Return partial answer rather than failing completely
		answer.RData = fmt.Sprintf("(truncated: need %d bytes, have %d)", answer.RDLength, len(data)-offset)
		return answer, len(data), nil
	}

	rdata := data[offset : offset+int(answer.RDLength)]
	answer.RData = formatRData(answer.Type, rdata, data)
	offset += int(answer.RDLength)

	return answer, offset, nil
}

// formatRData converts raw RDATA to a human-readable string based on record type.
func formatRData(rrtype uint16, rdata []byte, fullMsg []byte) string {
	switch rrtype {
	case DNSTypeA:
		if len(rdata) >= 4 {
			return fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3])
		}
	case DNSTypeAAAA:
		if len(rdata) >= 16 {
			return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
				binary.BigEndian.Uint16(rdata[0:2]),
				binary.BigEndian.Uint16(rdata[2:4]),
				binary.BigEndian.Uint16(rdata[4:6]),
				binary.BigEndian.Uint16(rdata[6:8]),
				binary.BigEndian.Uint16(rdata[8:10]),
				binary.BigEndian.Uint16(rdata[10:12]),
				binary.BigEndian.Uint16(rdata[12:14]),
				binary.BigEndian.Uint16(rdata[14:16]))
		}
	case DNSTypeCNAME, DNSTypeNS, DNSTypePTR:
		if len(rdata) > 0 {
			// Try to parse the name from rdata with the full message for compression
			// We need the offset into the full message
			offset := findDNSSubstringOffset(fullMsg, rdata)
			if offset >= 0 {
				parsedName, _, parseErr := parseDNSName(fullMsg, offset)
				if parseErr == nil {
					return parsedName
				}
			}
		}
		// Fallback: try parsing from rdata directly (no compression)
		simpleName := parseSimpleLabels(rdata)
		return simpleName
	case DNSTypeMX:
		if len(rdata) >= 2 {
			preference := binary.BigEndian.Uint16(rdata[0:2])
			return fmt.Sprintf("%d %s", preference, formatRData(DNSTypeCNAME, rdata[2:], fullMsg))
		}
	case DNSTypeTXT:
		var txts []string
		off := 0
		for off < len(rdata) {
			if off >= len(rdata) {
				break
			}
			tlen := int(rdata[off])
			off++
			if off+tlen > len(rdata) {
				break
			}
			txts = append(txts, string(rdata[off:off+tlen]))
			off += tlen
		}
		return strings.Join(txts, " ")
	}

	return fmt.Sprintf("(%d bytes)", len(rdata))
}

// parseSimpleLabels parses DNS labels from raw data without compression.
func parseSimpleLabels(data []byte) string {
	var labels []string
	offset := 0
	for offset < len(data) {
		if offset >= len(data) {
			break
		}
		length := int(data[offset])
		offset++
		if length == 0 {
			break
		}
		if length > 63 || offset+length > len(data) {
			break
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(labels, ".")
}

// findDNSSubstringOffset finds the offset of rdata within fullMsg.
func findDNSSubstringOffset(fullMsg []byte, rdata []byte) int {
	for i := 0; i <= len(fullMsg)-len(rdata); i++ {
		match := true
		for j := 0; j < len(rdata); j++ {
			if fullMsg[i+j] != rdata[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// ── DNS Suspicious Query Detection ─────────────────────────────────────

// DNSSuspiciousPatterns contains patterns that indicate suspicious DNS queries.
var DNSSuspiciousPatterns = []struct {
	Name        string
	Description string
	Check       func(name string) bool
}{
	{
		Name:        "long_subdomain",
		Description: "Unusually long subdomain chain (possible DGA or tunnel)",
		Check:       isLongSubdomain,
	},
	{
		Name:        "random_labels",
		Description: "Random-looking labels (possible DGA)",
		Check:       hasRandomLabels,
	},
	{
		Name:        "high_entropy",
		Description: "High entropy domain name (possible DGA or data exfil)",
		Check:       hasHighEntropy,
	},
	{
		Name:        "known_mining_pool",
		Description: "Known cryptocurrency mining pool domain",
		Check:       isKnownMiningPoolDomain,
	},
	{
		Name:        "known_malware_c2",
		Description: "Known malware C2 domain",
		Check:       isKnownMalwareC2Domain,
	},
}

// SuspiciousDNSQuery represents a suspicious DNS query detection result.
type SuspiciousDNSQuery struct {
	QueryName    string
	QueryType    uint16
	Patterns     []string // Pattern names that matched
	IsSuspicious bool
}

// CheckSuspiciousDNS evaluates a DNS query name against suspicious patterns.
func CheckSuspiciousDNS(name string, qtype uint16) *SuspiciousDNSQuery {
	result := &SuspiciousDNSQuery{
		QueryName: name,
		QueryType: qtype,
	}

	for _, pattern := range DNSSuspiciousPatterns {
		if pattern.Check(name) {
			result.Patterns = append(result.Patterns, pattern.Name)
		}
	}

	result.IsSuspicious = len(result.Patterns) > 0
	return result
}

// isLongSubdomain checks if a domain has an unusually deep subdomain chain.
func isLongSubdomain(name string) bool {
	labels := strings.Split(name, ".")
	// More than 5 labels is unusually deep (e.g., 1.2.3.4.5.example.com)
	return len(labels) > 5
}

// hasRandomLabels checks if the domain looks like it contains random strings.
func hasRandomLabels(name string) bool {
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}

	// Check the first label for randomness
	label := labels[0]
	if len(label) < 8 {
		return false
	}

	// Count unique characters
	chars := make(map[rune]bool)
	for _, c := range label {
		chars[c] = true
	}

	// If more than 80% of characters are unique and the label is long enough,
	// it's likely random
	ratio := float64(len(chars)) / float64(len(label))
	return ratio > 0.8 && len(label) >= 8
}

// hasHighEntropy checks if a domain name has high entropy.
func hasHighEntropy(name string) bool {
	if len(name) < 10 {
		return false
	}

	// Calculate character frequency
	freq := make(map[rune]float64)
	for _, c := range name {
		freq[c]++
	}

	// Calculate Shannon entropy
	var entropy float64
	n := float64(len(name))
	for _, count := range freq {
		p := count / n
		if p > 0 {
			// log2(p) = math.Log2(p), but we inline it
			// since math import would add weight for just this function
			// ln(2) ≈ 0.6931471805599453
			// log2(p) = math.Log(p) / math.Log(2)
			// We use a fast approximation
			if p > 0 {
				entropy -= p * shannonLog2(p)
			}
		}
	}

	// High entropy threshold (> 3.5 bits) indicates randomness
	return entropy > 3.5
}

// shannonLog2 computes log base 2 using a lookup/approximation approach
// that avoids importing the math package.
func shannonLog2(p float64) float64 {
	// Fast log2 approximation using bit manipulation
	// For entropy calculation, we need reasonable accuracy
	// log2(x) = 2*(x-1)/(x+1) + 2*(x-1)^3/(3*(x+1)^3) + ... (series)
	// But simpler: use the fact that log2(p) = -log2(1/p) when p < 1
	// For our use case, we use a rational approximation

	if p <= 0 {
		return 0
	}
	if p == 1 {
		return 0
	}
	if p == 0.5 {
		return -1
	}

	// Count leading zero bits for approximate log2
	// Use lookup table for common fractions
	switch {
	case p >= 0.4:
		return -1.25 // ~log2(0.4..0.5)
	case p >= 0.2:
		return -2.25 // ~log2(0.2..0.4)
	case p >= 0.1:
		return -3.25 // ~log2(0.1..0.2)
	case p >= 0.05:
		return -4.25 // ~log2(0.05..0.1)
	default:
		return -5.0 // rough upper bound
	}
}

func log2(x float64) float64 {
	return shannonLog2(x)
}

// isKnownMiningPoolDomain checks if a domain matches known mining pool patterns.
func isKnownMiningPoolDomain(name string) bool {
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
		"pool.minexmr",
		"stratum",
		"xmrpool",
		"dwarfpool",
		"mining.flexpool",
		"pool.hashrate",
	}

	lower := strings.ToLower(name)
	for _, pattern := range miningPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// isKnownMalwareC2Domain checks if a domain matches known C2 patterns.
func isKnownMalwareC2Domain(name string) bool {
	// These are pattern-based heuristics, not an exhaustive blocklist
	c2Patterns := []string{
		".onion.", // Tor hidden services (suspicious in container context)
		".bit.",   // Namecoin domains
		".tk.",    // Free TLD often abused
		".ml.",    // Free TLD often abused
		".ga.",    // Free TLD often abused
		".cf.",    // Free TLD often abused
	}

	lower := strings.ToLower(name)
	for _, pattern := range c2Patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// ── DNS Type Name Helpers ──────────────────────────────────────────────

// DNSTypeName maps DNS record type numbers to human-readable names.
var DNSTypeName = map[uint16]string{
	DNSTypeA:     "A",
	DNSTypeNS:    "NS",
	DNSTypeCNAME: "CNAME",
	DNSTypeSOA:   "SOA",
	DNSTypePTR:   "PTR",
	DNSTypeMX:    "MX",
	DNSTypeTXT:   "TXT",
	DNSTypeAAAA:  "AAAA",
	DNSTypeSRV:   "SRV",
	DNSTypeANY:   "ANY",
}

// DNSTypeNameString returns the name of a DNS record type.
func DNSTypeNameString(t uint16) string {
	if name, ok := DNSTypeName[t]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", t)
}
