package ebpf

import (
	"testing"
)

// ── DNS Parsing Tests ──────────────────────────────────────────────────

// buildDNSQuery creates a minimal DNS query message for testing.
func buildDNSQuery(name string, qtype uint16) []byte {
	// DNS Header (12 bytes)
	header := []byte{
		0xAA, 0xBB, // ID
		0x01, 0x00, // Flags: standard query
		0x00, 0x01, // QDCOUNT: 1 question
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
	}

	// Question section
	question := encodeDNSName(name)
	question = append(question, byte(qtype>>8), byte(qtype&0xFF)) // QTYPE
	question = append(question, 0x00, 0x01)                       // QCLASS = IN

	return append(header, question...)
}

// buildDNSResponse creates a DNS response message with answers for testing.
func buildDNSResponse(name string, qtype uint16, answer string) []byte {
	// DNS Header
	header := []byte{
		0xAA, 0xBB, // ID
		0x81, 0x80, // Flags: standard response, recursion available
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x01, // ANCOUNT: 1
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
	}

	// Question section
	question := encodeDNSName(name)
	question = append(question, byte(qtype>>8), byte(qtype&0xFF))
	question = append(question, 0x00, 0x01)

	// Answer section (using compression pointer for name)
	answerSection := []byte{0xC0, 0x0C} // pointer to question name
	answerSection = append(answerSection, byte(qtype>>8), byte(qtype&0xFF))
	answerSection = append(answerSection, 0x00, 0x01)             // CLASS IN
	answerSection = append(answerSection, 0x00, 0x00, 0x01, 0x00) // TTL = 256
	answerSection = append(answerSection, 0x00, 0x04)             // RDLENGTH

	switch qtype {
	case DNSTypeA:
		answerSection = append(answerSection, 1, 2, 3, 4) // 1.2.3.4
	default:
		answerSection = append(answerSection, 0, 0, 0, 0) // placeholder
	}

	return append(append(header, question...), answerSection...)
}

// encodeDNSName encodes a domain name in DNS wire format.
func encodeDNSName(name string) []byte {
	var result []byte
	parts := splitDomain(name)
	for _, part := range parts {
		result = append(result, byte(len(part)))
		result = append(result, []byte(part)...)
	}
	result = append(result, 0x00) // root label
	return result
}

// splitDomain splits a domain name by dots.
func splitDomain(name string) []string {
	var parts []string
	current := ""
	for _, c := range name {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func TestParseDNSMessage_Query(t *testing.T) {
	data := buildDNSQuery("example.com", DNSTypeA)
	msg, err := ParseDNSMessage(data)
	if err != nil {
		t.Fatalf("ParseDNSMessage failed: %v", err)
	}

	if msg.Header.ID != 0xAABB {
		t.Errorf("Expected ID=0xAABB, got 0x%04X", msg.Header.ID)
	}
	if !msg.IsQuery() {
		t.Error("Expected query (QR=0)")
	}
	if msg.Header.QDCount != 1 {
		t.Errorf("Expected QDCOUNT=1, got %d", msg.Header.QDCount)
	}
	if len(msg.Questions) != 1 {
		t.Fatalf("Expected 1 question, got %d", len(msg.Questions))
	}
	if msg.Questions[0].Name != "example.com" {
		t.Errorf("Expected question name=example.com, got %s", msg.Questions[0].Name)
	}
	if msg.Questions[0].Type != DNSTypeA {
		t.Errorf("Expected question type=A(1), got %d", msg.Questions[0].Type)
	}
}

func TestParseDNSMessage_Response(t *testing.T) {
	data := buildDNSResponse("test.example.com", DNSTypeA, "1.2.3.4")
	msg, err := ParseDNSMessage(data)
	if err != nil {
		t.Fatalf("ParseDNSMessage failed: %v", err)
	}

	if !msg.IsResponse() {
		t.Error("Expected response (QR=1)")
	}
	if msg.Header.QDCount != 1 {
		t.Errorf("Expected QDCOUNT=1, got %d", msg.Header.QDCount)
	}
	if msg.Header.ANCount != 1 {
		t.Errorf("Expected ANCOUNT=1, got %d", msg.Header.ANCount)
	}
}

func TestParseDNSMessage_TooShort(t *testing.T) {
	_, err := ParseDNSMessage([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Error("Expected error for too-short data")
	}
}

func TestParseDNSMessage_AAQuery(t *testing.T) {
	data := buildDNSQuery("a.example.com", DNSTypeAAAA)
	msg, err := ParseDNSMessage(data)
	if err != nil {
		t.Fatalf("ParseDNSMessage failed: %v", err)
	}
	if len(msg.Questions) != 1 {
		t.Fatalf("Expected 1 question, got %d", len(msg.Questions))
	}
	if msg.Questions[0].Name != "a.example.com" {
		t.Errorf("Expected name=a.example.com, got %s", msg.Questions[0].Name)
	}
	if msg.Questions[0].Type != DNSTypeAAAA {
		t.Errorf("Expected type=AAAA(28), got %d", msg.Questions[0].Type)
	}
}

func TestDNSMessage_IsQuery_IsResponse(t *testing.T) {
	query := buildDNSQuery("test.com", DNSTypeA)
	msg, _ := ParseDNSMessage(query)
	if !msg.IsQuery() {
		t.Error("Expected IsQuery=true")
	}
	if msg.IsResponse() {
		t.Error("Expected IsResponse=false")
	}

	response := buildDNSResponse("test.com", DNSTypeA, "1.2.3.4")
	msg2, _ := ParseDNSMessage(response)
	if msg2.IsQuery() {
		t.Error("Expected IsQuery=false for response")
	}
	if !msg2.IsResponse() {
		t.Error("Expected IsResponse=true for response")
	}
}

func TestDNSMessage_Rcode(t *testing.T) {
	data := buildDNSQuery("test.com", DNSTypeA)
	msg, _ := ParseDNSMessage(data)
	if msg.Rcode() != DNSRcodeNoError {
		t.Errorf("Expected RCODE=0 (NoError), got %d", msg.Rcode())
	}
}

func TestDNSMessage_OpCode(t *testing.T) {
	data := buildDNSQuery("test.com", DNSTypeA)
	msg, _ := ParseDNSMessage(data)
	if msg.OpCode() != 0 {
		t.Errorf("Expected OPCODE=0 (Standard Query), got %d", msg.OpCode())
	}
}

func TestDNSMessage_Truncated(t *testing.T) {
	data := buildDNSQuery("test.com", DNSTypeA)
	// Set TC bit (bit 9 in flags = 0x0200)
	data[2] |= 0x02
	msg, _ := ParseDNSMessage(data)
	if !msg.Truncated() {
		t.Error("Expected Truncated=true")
	}
}

func TestDNSTypeNameString(t *testing.T) {
	tests := []struct {
		qtype uint16
		name  string
	}{
		{DNSTypeA, "A"},
		{DNSTypeAAAA, "AAAA"},
		{DNSTypeCNAME, "CNAME"},
		{DNSTypeMX, "MX"},
		{DNSTypeTXT, "TXT"},
		{DNSTypeNS, "NS"},
		{DNSTypePTR, "PTR"},
		{999, "TYPE999"},
	}

	for _, tt := range tests {
		got := DNSTypeNameString(tt.qtype)
		if got != tt.name {
			t.Errorf("DNSTypeNameString(%d) = %q, want %q", tt.qtype, got, tt.name)
		}
	}
}

func TestIsDNSPort(t *testing.T) {
	if !IsDNSPort(53) {
		t.Error("Expected port 53 to be DNS port")
	}
	if IsDNSPort(80) {
		t.Error("Expected port 80 to NOT be DNS port")
	}
}

// ── Suspicious DNS Query Tests ─────────────────────────────────────────

func TestCheckSuspiciousDNS_LongSubdomain(t *testing.T) {
	result := CheckSuspiciousDNS("a.b.c.d.e.f.example.com", DNSTypeA)
	found := false
	for _, p := range result.Patterns {
		if p == "long_subdomain" {
			found = true
		}
	}
	if !found {
		t.Error("Expected long_subdomain pattern match for 7-label domain")
	}
}

func TestCheckSuspiciousDNS_NormalDomain(t *testing.T) {
	result := CheckSuspiciousDNS("www.example.com", DNSTypeA)
	if result.IsSuspicious {
		t.Error("Expected normal domain to not be suspicious")
	}
}

func TestCheckSuspiciousDNS_MiningPool(t *testing.T) {
	miningDomains := []string{
		"pool.minexmr.com",
		"stratum.ethereum.org",
		"nanopool.org",
		"ethermine.org",
	}
	for _, domain := range miningDomains {
		result := CheckSuspiciousDNS(domain, DNSTypeA)
		found := false
		for _, p := range result.Patterns {
			if p == "known_mining_pool" {
				found = true
			}
		}
		if !found {
			t.Errorf("Expected known_mining_pool pattern for %s", domain)
		}
	}
}

func TestCheckSuspiciousDNS_MalwareC2(t *testing.T) {
	c2Domains := []string{
		"something.bit.",
		"evil.tk.",
		"malware.ml.",
	}
	for _, domain := range c2Domains {
		result := CheckSuspiciousDNS(domain, DNSTypeA)
		found := false
		for _, p := range result.Patterns {
			if p == "known_malware_c2" {
				found = true
			}
		}
		if !found {
			t.Errorf("Expected known_malware_c2 pattern for %s (patterns: %v)", domain, result.Patterns)
		}
	}
}

func TestCheckSuspiciousDNS_RandomLabels(t *testing.T) {
	// Random-looking label (should match)
	result := CheckSuspiciousDNS("xKz9mQp2rFg8hJ.example.com", DNSTypeA)
	found := false
	for _, p := range result.Patterns {
		if p == "random_labels" {
			found = true
		}
	}
	if !found {
		t.Error("Expected random_labels pattern for random-looking domain")
	}

	// Normal label (should not match)
	result2 := CheckSuspiciousDNS("www.example.com", DNSTypeA)
	for _, p := range result2.Patterns {
		if p == "random_labels" {
			t.Error("Did not expect random_labels for normal domain")
		}
	}
}

func TestCheckSuspiciousDNS_QueryName(t *testing.T) {
	result := CheckSuspiciousDNS("stratum.example.com", DNSTypeA)
	if result.QueryName != "stratum.example.com" {
		t.Errorf("Expected QueryName=stratum.example.com, got %s", result.QueryName)
	}
	if result.QueryType != DNSTypeA {
		t.Errorf("Expected QueryType=A, got %d", result.QueryType)
	}
}

// ── TLS SNI Extraction Tests ────────────────────────────────────────────

// buildTLSClientHello creates a minimal TLS ClientHello with SNI for testing.
func buildTLSClientHello(sni string) []byte {
	// SNI extension payload
	sniEntry := []byte{
		byte(TLSExtensionSNIHostName), // Name Type: host_name
	}
	sniNameBytes := []byte(sni)
	sniEntry = append(sniEntry, byte(len(sniNameBytes)>>8), byte(len(sniNameBytes)&0xFF))
	sniEntry = append(sniEntry, sniNameBytes...)

	sniExtPayload := []byte{byte(len(sniEntry) >> 8), byte(len(sniEntry) & 0xFF)}
	sniExtPayload = append(sniExtPayload, sniEntry...)

	// Full extension: type (0x0000) + length + data
	sniExtension := []byte{0x00, 0x00} // Extension type: server_name (0)
	sniExtLen := len(sniExtPayload)
	sniExtension = append(sniExtension, byte(sniExtLen>>8), byte(sniExtLen&0xFF))
	sniExtension = append(sniExtension, sniExtPayload...)

	// Extensions block length
	extensionsLen := len(sniExtension)
	extensions := []byte{byte(extensionsLen >> 8), byte(extensionsLen & 0xFF)}
	extensions = append(extensions, sniExtension...)

	// Handshake body: ClientVersion(2) + Random(32) + SessionID(1+0) + CipherSuites(2+2) + CompressionMethods(1+1) + Extensions
	clientHelloBody := []byte{
		0x03, 0x03, // ClientVersion: TLS 1.2
	}
	// Random (32 bytes)
	for i := 0; i < 32; i++ {
		clientHelloBody = append(clientHelloBody, byte(i))
	}
	// Session ID (0 length)
	clientHelloBody = append(clientHelloBody, 0x00)
	// Cipher Suites (2 bytes length + 1 cipher)
	clientHelloBody = append(clientHelloBody, 0x00, 0x02, 0x00, 0x2F) // TLS_RSA_WITH_AES_128_CBC_SHA
	// Compression Methods (1 byte length + 1 method)
	clientHelloBody = append(clientHelloBody, 0x01, 0x00) // null compression
	// Extensions
	clientHelloBody = append(clientHelloBody, extensions...)

	// Handshake header: Type(1) + Length(3) + body
	handshakeLen := len(clientHelloBody)
	handshake := []byte{byte(TLSHandshakeTypeClientHello)}
	handshake = append(handshake, byte(handshakeLen>>16), byte(handshakeLen>>8), byte(handshakeLen&0xFF))
	handshake = append(handshake, clientHelloBody...)

	// TLS record: ContentType(1) + Version(2) + Length(2) + handshake
	recordLen := len(handshake)
	record := []byte{
		byte(TLSContentTypeHandshake),
		0x03, 0x03, // TLS 1.2
		byte(recordLen >> 8), byte(recordLen & 0xFF),
	}
	record = append(record, handshake...)

	return record
}

func TestExtractTLSClientHelloSNI_BasicSNI(t *testing.T) {
	payload := buildTLSClientHello("example.com")
	result := ExtractTLSClientHelloSNI(payload)

	if !result.HasSNI {
		t.Fatal("Expected HasSNI=true")
	}
	if result.SNI != "example.com" {
		t.Errorf("Expected SNI=example.com, got %s", result.SNI)
	}
	if result.TLSVersion != 0x0303 {
		t.Errorf("Expected TLSVersion=0x0303 (TLS 1.2), got 0x%04X", result.TLSVersion)
	}
}

func TestExtractTLSClientHelloSNI_SuspiciousMiningPool(t *testing.T) {
	payload := buildTLSClientHello("stratum.minexmr.com")
	result := ExtractTLSClientHelloSNI(payload)

	if !result.HasSNI {
		t.Fatal("Expected HasSNI=true")
	}
	if !result.IsSuspicious {
		t.Error("Expected IsSuspicious=true for mining pool SNI")
	}
	found := false
	for _, reason := range result.SuspiciousReasons {
		if reason == "mining_pool_domain" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected mining_pool_domain reason, got %v", result.SuspiciousReasons)
	}
}

func TestExtractTLSClientHelloSNI_SuspiciousTLD(t *testing.T) {
	payload := buildTLSClientHello("evil.tk")
	result := ExtractTLSClientHelloSNI(payload)

	if !result.HasSNI {
		t.Fatal("Expected HasSNI=true")
	}
	if !result.IsSuspicious {
		t.Error("Expected IsSuspicious=true for suspicious TLD")
	}
}

func TestExtractTLSClientHelloSNI_NormalDomain(t *testing.T) {
	payload := buildTLSClientHello("www.google.com")
	result := ExtractTLSClientHelloSNI(payload)

	if !result.HasSNI {
		t.Fatal("Expected HasSNI=true")
	}
	if result.IsSuspicious {
		t.Errorf("Expected IsSuspicious=false for normal domain, reasons: %v", result.SuspiciousReasons)
	}
}

func TestExtractTLSClientHelloSNI_TorOnion(t *testing.T) {
	payload := buildTLSClientHello("abcdef123456.onion")
	result := ExtractTLSClientHelloSNI(payload)

	if !result.HasSNI {
		t.Fatal("Expected HasSNI=true")
	}
	if !result.IsSuspicious {
		t.Error("Expected IsSuspicious=true for .onion SNI")
	}
}

func TestExtractTLSClientHelloSNI_EmptyPayload(t *testing.T) {
	result := ExtractTLSClientHelloSNI([]byte{})
	if result.HasSNI {
		t.Error("Expected HasSNI=false for empty payload")
	}
}

func TestExtractTLSClientHelloSNI_TooShort(t *testing.T) {
	result := ExtractTLSClientHelloSNI([]byte{0x16, 0x03, 0x01})
	if result.HasSNI {
		t.Error("Expected HasSNI=false for too-short payload")
	}
}

func TestExtractTLSClientHelloSNI_NotHandshake(t *testing.T) {
	// ContentType 23 = Application Data, not Handshake
	result := ExtractTLSClientHelloSNI([]byte{0x17, 0x03, 0x03, 0x00, 0x02, 0x00, 0x00})
	if result.HasSNI {
		t.Error("Expected HasSNI=false for non-Handshake content type")
	}
}

func TestExtractTLSClientHelloSNI_NotClientHello(t *testing.T) {
	// Build a TLS record with Handshake type but not ClientHello
	record := []byte{
		byte(TLSContentTypeHandshake), 0x03, 0x03, // TLS 1.2
		0x00, 0x0E, // record length
		0x02,             // HandshakeType: ServerHello (not ClientHello)
		0x00, 0x00, 0x0A, // Handshake length
		0x03, 0x03, // ServerVersion
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	result := ExtractTLSClientHelloSNI(record)
	if result.HasSNI {
		t.Error("Expected HasSNI=false for non-ClientHello handshake")
	}
}

// TestSNISuspiciousChecks verifies SNI suspicious pattern checks
func TestSNISuspiciousChecks(t *testing.T) {
	tests := []struct {
		sni        string
		suspicious bool
	}{
		{"www.example.com", false},
		{"stratum.minexmr.com", true},       // mining_pool_domain
		{"evil.tk", true},                   // suspicious_tld
		{"abcdef1234567890xyz.onion", true}, // tor_hidden_service
		{"192.168.1.1", true},               // ip_address_sni
	}

	for _, tt := range tests {
		reasons := CheckSuspiciousSNI(tt.sni)
		isSusp := len(reasons) > 0
		if isSusp != tt.suspicious {
			t.Errorf("CheckSuspiciousSNI(%q): suspicious=%v, want %v, reasons=%v", tt.sni, isSusp, tt.suspicious, reasons)
		}
	}
}
