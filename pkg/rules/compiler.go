// Package rules - compiler.go
// Compiles YAML rule conditions into Go functions for fast-path evaluation.
// The compilation approach converts declarative condition strings into closures
// that can be evaluated with zero heap allocation.
//
// The condition compiler builds an expression tree from the condition string,
// respecting parenthesis grouping and operator precedence:
//   - "or" has lower precedence (splits first → evaluated last)
//   - "and" has higher precedence (splits second → evaluated first)
//   - Parentheses override precedence
//   - "not" is a unary prefix negation operator
//   - "not in" is a compound operator for set exclusion

package rules

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/securityscarlet/runtime/pkg/ebpf"
)

// ── Expression Tree Types ─────────────────────────────────────────────

// ConditionExpr represents a node in the condition expression tree.
type ConditionExpr struct {
	Op    string          // "and", "or", "not", "leaf"
	Leaf  *ConditionCheck // only for Op="leaf"
	Left  *ConditionExpr  // for "and"/"or"/"not" nodes
	Right *ConditionExpr  // for "and"/"or" nodes (nil for "not")
}

// ConditionCheck represents a single atomic check in a rule condition.
type ConditionCheck struct {
	// Field to check
	Field string // e.g., "proc.name", "evt.type", "container"

	// Operator
	Op string // in, not_in, contains, startswith, pmatch, =, !=

	// Values to check against
	Values []string
}

// ── Condition Compilation (entry point) ────────────────────────────────

// compileCondition converts a condition string into a RuleCondition function.
// This is the fast-path compiler that avoids runtime string parsing.
func (e *Engine) compileCondition(condition string, macros map[string]MacroDef) (RuleCondition, error) {
	// Normalize whitespace: YAML folded scalars (>) may preserve newlines
	// for indented continuation lines, which breaks " or "/" and " operator
	// detection. Collapse all whitespace runs to single spaces.
	condition = normalizeWhitespace(condition)

	// Expand macros in the condition
	expanded := e.expandMacros(condition, macros)

	// Parse the expanded condition into an expression tree
	expr, err := e.parseConditionExpr(expanded)
	if err != nil {
		return nil, err
	}

	// Compile expression tree into a closure
	return e.compileExpr(expr)
}

// normalizeWhitespace collapses all runs of whitespace (spaces, tabs,
// newlines, carriage returns) to single spaces, and trims leading/trailing
// whitespace. This fixes YAML folded scalar newlines that break operator
// detection for " or " and " and ".
func normalizeWhitespace(s string) string {
	return strings.TrimSpace(whitespaceRe.ReplaceAllString(s, " "))
}

// whitespaceRe matches any run of one or more whitespace characters.
var whitespaceRe = regexp.MustCompile(`\s+`)

// ── Macro Expansion ────────────────────────────────────────────────────

// expandMacros replaces macro references with their condition definitions.
// Uses token-boundary matching to only replace standalone macro names
// (surrounded by whitespace, parens, commas, or string boundaries).
// This avoids replacing macro names inside other identifiers like
// "container" inside "container_id" or "container.id".
func (e *Engine) expandMacros(condition string, macros map[string]MacroDef) string {
	// Iteratively expand macros (support nested macros)
	for i := 0; i < 10; i++ { // max 10 expansion rounds
		changed := false
		for name, macro := range macros {
			// Match the macro name only as a standalone token:
			// preceded by: start, whitespace, '(', ','
			// followed by: end, whitespace, ')', ','
			re := regexp.MustCompile(`(^|[\s(,])` + regexp.QuoteMeta(name) + `($|[\s),])`)
			if re.MatchString(condition) {
				condition = re.ReplaceAllString(condition, "${1}("+macro.Condition+")${2}")
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return condition
}

// ── Expression Tree Parser ─────────────────────────────────────────────

// parseConditionExpr is the top-level parser entry point.
// It lowercases the condition (field/operator names are case-insensitive)
// and delegates to the precedence-aware recursive descent parser.
func (e *Engine) parseConditionExpr(condition string) (*ConditionExpr, error) {
	condition = strings.ToLower(strings.TrimSpace(condition))
	if condition == "" {
		return nil, fmt.Errorf("empty condition")
	}
	return e.parseOrExpr(condition)
}

// parseOrExpr splits on " or " at parenthesis depth 0 and builds an OR tree.
// "or" has lower precedence than "and", so it's parsed first (outermost).
func (e *Engine) parseOrExpr(expr string) (*ConditionExpr, error) {
	parts := splitAtDepth0(expr, " or ")
	if len(parts) == 1 {
		return e.parseAndExpr(parts[0])
	}

	// Build a left-associative OR tree
	node, err := e.parseAndExpr(parts[0])
	if err != nil {
		return nil, err
	}
	for i := 1; i < len(parts); i++ {
		right, err := e.parseAndExpr(parts[i])
		if err != nil {
			return nil, err
		}
		if right != nil {
			node = &ConditionExpr{Op: "or", Left: node, Right: right}
		}
	}
	return node, nil
}

// parseAndExpr splits on " and " at parenthesis depth 0 and builds an AND tree.
// "and" has higher precedence than "or", so it's parsed second (inner).
func (e *Engine) parseAndExpr(expr string) (*ConditionExpr, error) {
	parts := splitAtDepth0(expr, " and ")
	if len(parts) == 1 {
		return e.parseLeafExpr(parts[0])
	}

	// Build a left-associative AND tree
	node, err := e.parseLeafExpr(parts[0])
	if err != nil {
		return nil, err
	}
	for i := 1; i < len(parts); i++ {
		right, err := e.parseLeafExpr(parts[i])
		if err != nil {
			return nil, err
		}
		if right != nil {
			node = &ConditionExpr{Op: "and", Left: node, Right: right}
		}
	}
	return node, nil
}

// parseLeafExpr handles a leaf condition (no boolean operators at the current level).
// It strips matching outer parentheses, handles "not" prefix negation,
// detects sub-expressions that need re-parsing, and delegates to parseSingleCheck
// for atomic condition parsing.
func (e *Engine) parseLeafExpr(expr string) (*ConditionExpr, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("empty leaf expression")
	}

	// Handle "not" prefix as unary negation
	if strings.HasPrefix(expr, "not ") {
		inner, err := e.parseLeafExpr(expr[4:])
		if err != nil {
			return nil, err
		}
		return &ConditionExpr{Op: "not", Left: inner}, nil
	}

	// Strip matching outer parentheses (may need multiple passes)
	for {
		stripped, changed := stripOuterParens(expr)
		if !changed {
			break
		}
		expr = strings.TrimSpace(stripped)
	}

	// After stripping parens, check for boolean operators at depth 0
	// — if found, this isn't a leaf; re-parse as a sub-expression
	if containsOperatorAtDepth0(expr, " or ") || containsOperatorAtDepth0(expr, " and ") {
		return e.parseOrExpr(expr)
	}

	// Parse as a single atomic check
	check, err := e.parseSingleCheck(expr)
	if err != nil {
		// Unparseable check: log warning and return a false-yielding leaf
		log.Printf("[rules] Warning: unparseable condition %q: %v, treating as false", expr, err)
		return &ConditionExpr{
			Op:   "leaf",
			Leaf: &ConditionCheck{Field: "passthrough", Op: "false", Values: nil},
		}, nil
	}

	return &ConditionExpr{Op: "leaf", Leaf: &check}, nil
}

// ── Depth-Aware Splitting Helpers ──────────────────────────────────────

// splitAtDepth0 splits a string on the given separator, but only at
// parenthesis depth 0. This respects parenthesized sub-expressions.
func splitAtDepth0(s, sep string) []string {
	var parts []string
	depth := 0
	start := 0

	for i := 0; i < len(s); i++ {
		if s[i] == '(' {
			depth++
		} else if s[i] == ')' {
			depth--
		}
		if depth == 0 && i <= len(s)-len(sep) && s[i:i+len(sep)] == sep {
			parts = append(parts, strings.TrimSpace(s[start:i]))
			start = i + len(sep)
			i += len(sep) - 1 // skip past the separator
		}
	}
	parts = append(parts, strings.TrimSpace(s[start:]))
	return parts
}

// stripOuterParens strips one level of matching outer parentheses.
// Returns the stripped string and whether any stripping occurred.
// Only strips if the opening paren at position 0 and the closing paren
// at the last position are a matched pair that wraps the entire expression.
func stripOuterParens(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return s, false
	}

	// Verify these are matching outer parens by checking depth balance
	depth := 0
	for i, c := range s {
		if c == '(' {
			depth++
		} else if c == ')' {
			depth--
		}
		if depth == 0 && i < len(s)-1 {
			// Reached balance before the end — outer parens don't wrap the whole expression
			return s, false
		}
	}

	if depth == 0 {
		return s[1 : len(s)-1], true
	}
	return s, false
}

// containsOperatorAtDepth0 checks if a string contains the given operator
// at parenthesis depth 0.
func containsOperatorAtDepth0(s, op string) bool {
	depth := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '(' {
			depth++
		} else if s[i] == ')' {
			depth--
		}
		if depth == 0 && i <= len(s)-len(op) && s[i:i+len(op)] == op {
			return true
		}
	}
	return false
}

// ── Expression Tree Compiler ───────────────────────────────────────────

// compileExpr compiles an expression tree into a RuleCondition closure.
// It recursively compiles the tree, producing nested closures that respect
// boolean semantics: AND → short-circuit &&, OR → short-circuit ||, NOT → !.
func (e *Engine) compileExpr(expr *ConditionExpr) (RuleCondition, error) {
	switch expr.Op {
	case "and":
		left, err := e.compileExpr(expr.Left)
		if err != nil {
			return nil, err
		}
		right, err := e.compileExpr(expr.Right)
		if err != nil {
			return nil, err
		}
		return func(event *EnrichedEventForRule) bool {
			return left(event) && right(event)
		}, nil

	case "or":
		left, err := e.compileExpr(expr.Left)
		if err != nil {
			return nil, err
		}
		right, err := e.compileExpr(expr.Right)
		if err != nil {
			return nil, err
		}
		return func(event *EnrichedEventForRule) bool {
			return left(event) || right(event)
		}, nil

	case "not":
		inner, err := e.compileExpr(expr.Left)
		if err != nil {
			return nil, err
		}
		return func(event *EnrichedEventForRule) bool {
			return !inner(event)
		}, nil

	case "leaf":
		if expr.Leaf == nil {
			return func(event *EnrichedEventForRule) bool { return false }, nil
		}
		fn := e.compileSingleCheck(*expr.Leaf)
		return fn, nil

	default:
		return func(event *EnrichedEventForRule) bool { return false }, nil
	}
}

// ── Single Check Parser ───────────────────────────────────────────────

// parseSingleCheck parses a single condition expression like "proc.name in (shell_binaries)".
// This handles all atomic operators: in, not_in, contains, startswith, pmatch, =, !=.
func (e *Engine) parseSingleCheck(expr string) (ConditionCheck, error) {
	check := ConditionCheck{}

	// Handle "container" shorthand (no operator)
	if expr == "container" || expr == "container.id != host" {
		return ConditionCheck{Field: "container", Op: "is_container", Values: nil}, nil
	}

	// Handle "not in" operator (must check BEFORE "in" to avoid partial match)
	if strings.Contains(expr, " not in ") {
		parts := strings.SplitN(expr, " not in ", 2)
		check.Field = strings.TrimSpace(parts[0])
		check.Op = "not_in"
		// Parse value list name or literal list
		valStr := strings.TrimSpace(parts[1])
		if strings.HasPrefix(valStr, "(") && strings.HasSuffix(valStr, ")") {
			valStr = valStr[1 : len(valStr)-1]
		}
		// Check if it's a list reference
		if list, ok := e.lists[valStr]; ok {
			check.Values = list.Items
		} else {
			check.Values = strings.Split(valStr, ",")
			for i := range check.Values {
				check.Values[i] = strings.TrimSpace(check.Values[i])
			}
		}
		return check, nil
	}

	// Handle "in" operator
	if strings.Contains(expr, " in ") {
		parts := strings.SplitN(expr, " in ", 2)
		check.Field = strings.TrimSpace(parts[0])
		check.Op = "in"
		// Parse value list name or literal list
		valStr := strings.TrimSpace(parts[1])
		if strings.HasPrefix(valStr, "(") && strings.HasSuffix(valStr, ")") {
			valStr = valStr[1 : len(valStr)-1]
		}
		// Check if it's a list reference
		if list, ok := e.lists[valStr]; ok {
			check.Values = list.Items
		} else {
			check.Values = strings.Split(valStr, ",")
			for i := range check.Values {
				check.Values[i] = strings.TrimSpace(check.Values[i])
			}
		}
		return check, nil
	}

	// Handle "contains" operator
	if strings.Contains(expr, " contains ") {
		parts := strings.SplitN(expr, " contains ", 2)
		check.Field = strings.TrimSpace(parts[0])
		check.Op = "contains"
		valStr := strings.TrimSpace(parts[1])
		// Strip parens from value if present
		if strings.HasPrefix(valStr, "(") && strings.HasSuffix(valStr, ")") && isBalanced(valStr) {
			valStr = valStr[1 : len(valStr)-1]
		}
		check.Values = []string{valStr}
		return check, nil
	}

	// Handle "startswith" operator
	if strings.Contains(expr, " startswith ") {
		parts := strings.SplitN(expr, " startswith ", 2)
		check.Field = strings.TrimSpace(parts[0])
		check.Op = "startswith"
		valStr := strings.TrimSpace(parts[1])
		// Strip parens from value if present
		if strings.HasPrefix(valStr, "(") && strings.HasSuffix(valStr, ")") && isBalanced(valStr) {
			valStr = valStr[1 : len(valStr)-1]
		}
		check.Values = []string{valStr}
		return check, nil
	}

	// Handle "pmatch" (path prefix match)
	if strings.Contains(expr, " pmatch ") {
		parts := strings.SplitN(expr, " pmatch ", 2)
		check.Field = strings.TrimSpace(parts[0])
		check.Op = "pmatch"
		valStr := strings.TrimSpace(parts[1])
		// Strip outer parens from value list if present
		if strings.HasPrefix(valStr, "(") && strings.HasSuffix(valStr, ")") && isBalanced(valStr) {
			valStr = valStr[1 : len(valStr)-1]
		}
		vals := strings.Split(valStr, ",")
		for i := range vals {
			vals[i] = strings.TrimSpace(vals[i])
		}
		check.Values = vals
		return check, nil
	}

	// Handle "=" operator
	if strings.Contains(expr, " = ") {
		parts := strings.SplitN(expr, " = ", 2)
		check.Field = strings.TrimSpace(parts[0])
		check.Op = "="
		check.Values = []string{strings.TrimSpace(parts[1])}
		return check, nil
	}

	// Handle "!=" operator
	if strings.Contains(expr, " != ") {
		parts := strings.SplitN(expr, " != ", 2)
		check.Field = strings.TrimSpace(parts[0])
		check.Op = "!="
		check.Values = []string{strings.TrimSpace(parts[1])}
		return check, nil
	}

	// Simple event type check fallback
	if strings.Contains(expr, "evt.type") {
		return ConditionCheck{Field: "evt.type", Op: "any", Values: nil}, nil
	}

	// Handle bare boolean fields (no operator) — fields that are
	// inherently true/false without needing a comparison value.
	switch expr {
	case "evt.is_open_exec":
		return ConditionCheck{Field: "evt.is_open_exec", Op: "bool", Values: nil}, nil
	}

	// Unrecognized — return false to avoid false positives
	return ConditionCheck{Field: "passthrough", Op: "false", Values: nil},
		fmt.Errorf("unrecognized condition: %q", expr)
}

// isBalanced checks if parentheses in a string are balanced and the
// first '(' matches the last ')'.
func isBalanced(s string) bool {
	if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return false
	}
	depth := 0
	for i, c := range s {
		if c == '(' {
			depth++
		} else if c == ')' {
			depth--
		}
		if depth == 0 && i < len(s)-1 {
			return false
		}
	}
	return depth == 0
}

// ── Single Check Compiler ─────────────────────────────────────────────

// compileSingleCheck compiles one ConditionCheck into an evaluation function.
func (e *Engine) compileSingleCheck(check ConditionCheck) func(*EnrichedEventForRule) bool {
	switch check.Field {
	case "container":
		return func(event *EnrichedEventForRule) bool {
			return event.ContainerAttributed && event.ContainerID != ""
		}

	case "evt.type":
		return e.compileEventTypeCheck(check)

	case "spawned_process", "setns_call", "net_outbound",
		"open_write", "minerpool_connection", "sensitive_file_read",
		"cloud_metadata_access", "shell_procs", "miner_procs":
		// Macro-derived checks that didn't get expanded — compile as macro shortcuts
		return e.compileMacroCheck(check)

	case "container.id":
		// "container.id != host" means it's a container (not host)
		if check.Op == "!=" && len(check.Values) > 0 && check.Values[0] == "host" {
			return func(event *EnrichedEventForRule) bool {
				return event.ContainerAttributed && event.ContainerID != ""
			}
		}
		return func(event *EnrichedEventForRule) bool { return false }

	case "proc.name":
		return e.compileFieldCheck("proc.name", check)

	case "proc.cmdline":
		return e.compileFieldCheck("proc.cmdline", check)

	case "proc.exe":
		return e.compileFieldCheck("proc.exe", check)

	case "proc.cwd":
		return e.compileFieldCheck("proc.cwd", check)

	case "fd.rip", "fd.rip.name":
		return e.compileFieldCheck("fd.rip", check)

	case "fd.rport":
		return e.compileFieldCheck("fd.rport", check)

	case "fd.name":
		return e.compileFieldCheck("fd.name", check)

	case "fd.type":
		// fd.type = socket — not directly available in Phase 1
		if check.Op == "=" && len(check.Values) > 0 {
			switch check.Values[0] {
			case "socket":
				return func(event *EnrichedEventForRule) bool {
					return event.Event.Category == ebpf.CatNetwork
				}
			case "file":
				return func(event *EnrichedEventForRule) bool {
					return event.Event.Category == ebpf.CatFile
				}
			}
		}
		return func(event *EnrichedEventForRule) bool { return false }

	case "fd.fd":
		// fd.fd in (0, 1, 2) — file descriptor check not available in Phase 1
		return func(event *EnrichedEventForRule) bool { return false }

	case "evt.arg.flags":
		return e.compileFieldCheck("evt.arg.flags", check)

	case "evt.arg.mode":
		return e.compileFieldCheck("evt.arg.mode", check)

	case "evt.arg.nstype":
		return e.compileFieldCheck("evt.arg.nstype", check)

	case "evt.is_open_exec":
		return func(event *EnrichedEventForRule) bool {
			// Check if the file open was an executable
			return event.Event.Category == ebpf.CatFile &&
				event.Event.Payload.File.Flags&0x01 != 0 // O_EXEC
		}

	case "evt.dir":
		// evt.dir = < (outbound direction)
		// In Phase 1, we assume all captured events are "<" (outbound/syscall enter)
		if check.Op == "=" && len(check.Values) > 0 && check.Values[0] == "<" {
			return func(event *EnrichedEventForRule) bool { return true }
		}
		return func(event *EnrichedEventForRule) bool { return false }

	case "passthrough":
		if check.Op == "true" {
			return func(event *EnrichedEventForRule) bool { return true }
		}
		// Op == "false" or anything else — return false (never matches)
		return func(event *EnrichedEventForRule) bool { return false }

	default:
		// Unknown field — return false to avoid false positives
		// Phase 2 will add full condition parser with OPA fallback
		log.Printf("[rules] Warning: unrecognized condition field %q in rule, treating as false", check.Field)
		return func(event *EnrichedEventForRule) bool { return false }
	}
}

// compileEventTypeCheck handles "evt.type" conditions.
// This maps syscall names (execve, setns, connect, etc.) to our internal event types.
func (e *Engine) compileEventTypeCheck(check ConditionCheck) func(*EnrichedEventForRule) bool {
	// Build a set of matching event types from the condition values
	matchingTypes := make(map[uint8]bool)

	switch check.Op {
	case "=":
		if len(check.Values) > 0 {
			if et := e.syscallToEventType(check.Values[0]); et != 0 {
				matchingTypes[et] = true
			} else {
				// Unknown syscall — this rule can never match
				return func(event *EnrichedEventForRule) bool { return false }
			}
		}

	case "in":
		for _, v := range check.Values {
			if et := e.syscallToEventType(v); et != 0 {
				matchingTypes[et] = true
			}
		}
		if len(matchingTypes) == 0 {
			return func(event *EnrichedEventForRule) bool { return false }
		}

	case "any":
		// Wildcard — match any event type
		return func(event *EnrichedEventForRule) bool { return true }

	default:
		return func(event *EnrichedEventForRule) bool { return false }
	}

	return func(event *EnrichedEventForRule) bool {
		return matchingTypes[event.Event.EventType]
	}
}

// syscallToEventType maps common Linux syscall names to our event type constants.
func (e *Engine) syscallToEventType(name string) uint8 {
	name = strings.ToLower(strings.TrimSpace(name))

	switch name {
	case "execve", "execveat":
		return ebpf.EvtExec
	case "fork", "clone", "clone3":
		return ebpf.EvtFork
	case "exit", "exit_group":
		return ebpf.EvtExit
	case "open", "openat", "openat2", "creat":
		return ebpf.EvtFileOpen
	case "unlinkat", "unlink":
		return ebpf.EvtFileUnlink
	case "memfd_create":
		return ebpf.EvtFileMemfd
	case "renameat", "renameat2", "rename":
		return ebpf.EvtFileRename
	case "connect", "sendto", "sendmsg":
		return ebpf.EvtNetConnect
	case "listen":
		return ebpf.EvtNetListen
	case "setns":
		return ebpf.EvtSetns
	case "unshare":
		return ebpf.EvtUnshare
	case "mount":
		return ebpf.EvtMount
	case "ptrace":
		return ebpf.EvtPtrace
	case "init_module", "finit_module":
		return ebpf.EvtModuleLoad
	case "bpf":
		return ebpf.EvtBpfLoad
	case "setuid", "setresuid":
		return ebpf.EvtSetuid
	case "capset":
		return ebpf.EvtCapset
	case "chmod", "fchmodat", "fchmod":
		return ebpf.EvtChmod
	case "dup2", "dup3", "dup":
		return ebpf.EvtNetConnect // mapped to net for reverse shell detection
	default:
		return 0 // unknown
	}
}

// compileMacroCheck handles macro-name checks that weren't fully expanded.
// These are fallback shortcuts for known macro names.
func (e *Engine) compileMacroCheck(check ConditionCheck) func(*EnrichedEventForRule) bool {
	switch check.Field {
	case "spawned_process":
		return func(event *EnrichedEventForRule) bool {
			return event.Event.EventType == ebpf.EvtExec
		}

	case "setns_call":
		return func(event *EnrichedEventForRule) bool {
			return event.Event.EventType == ebpf.EvtSetns
		}

	case "net_outbound":
		return func(event *EnrichedEventForRule) bool {
			return event.Event.Category == ebpf.CatNetwork &&
				(event.Event.EventType == ebpf.EvtNetConnect || event.Event.EventType == ebpf.EvtNetUDP)
		}

	case "shell_procs":
		return func(event *EnrichedEventForRule) bool {
			return ebpf.IsShellProcess(event.Event.CommString())
		}

	case "miner_procs":
		return func(event *EnrichedEventForRule) bool {
			return ebpf.IsMinerProcess(event.Event.CommString())
		}

	case "minerpool_connection":
		return func(event *EnrichedEventForRule) bool {
			if event.Event.Category != ebpf.CatNetwork {
				return false
			}
			port := event.Event.RemotePort()
			if ebpf.IsMinerPoolPort(port) {
				return true
			}
			return false
		}

	case "sensitive_file_read":
		return func(event *EnrichedEventForRule) bool {
			return event.Event.Category == ebpf.CatFile && event.Event.IsSensitivePath()
		}

	case "cloud_metadata_access":
		return func(event *EnrichedEventForRule) bool {
			if event.Event.Category != ebpf.CatNetwork {
				return false
			}
			return ebpf.IsCloudMetadataIP(event.Event.RemoteIP())
		}

	case "open_write":
		return func(event *EnrichedEventForRule) bool {
			if event.Event.Category != ebpf.CatFile || event.Event.EventType != ebpf.EvtFileOpen {
				return false
			}
			flags := event.Event.Payload.File.Flags
			return flags&1 != 0 || flags&2 != 0
		}

	default:
		// Unknown macro — return false to avoid false positives
		log.Printf("[rules] Warning: unrecognized macro %q in condition, treating as false", check.Field)
		return func(event *EnrichedEventForRule) bool { return false }
	}
}

// compileFieldCheck compiles a field check with operator and values.
func (e *Engine) compileFieldCheck(field string, check ConditionCheck) func(*EnrichedEventForRule) bool {
	valueSet := make(map[string]bool, len(check.Values))
	for _, v := range check.Values {
		valueSet[strings.ToLower(v)] = true
	}

	switch field {
	case "proc.name":
		switch check.Op {
		case "in":
			return func(event *EnrichedEventForRule) bool {
				return valueSet[strings.ToLower(event.Event.CommString())]
			}
		case "contains":
			return func(event *EnrichedEventForRule) bool {
				return strings.Contains(strings.ToLower(event.Event.CommString()), check.Values[0])
			}
		}

	case "proc.cmdline":
		return func(event *EnrichedEventForRule) bool {
			cmdline := strings.ToLower(event.Event.Args())
			for _, v := range check.Values {
				if strings.Contains(cmdline, strings.ToLower(v)) {
					return true
				}
			}
			return false
		}

	case "proc.exe":
		switch check.Op {
		case "startswith":
			return func(event *EnrichedEventForRule) bool {
				return strings.HasPrefix(event.Event.Filename(), check.Values[0])
			}
		case "contains":
			return func(event *EnrichedEventForRule) bool {
				return strings.Contains(strings.ToLower(event.Event.Filename()), check.Values[0])
			}
		}

	case "proc.cwd":
		switch check.Op {
		case "startswith":
			return func(event *EnrichedEventForRule) bool {
				return strings.HasPrefix(event.Event.Filename(), check.Values[0])
			}
		}

	case "fd.rport":
		return func(event *EnrichedEventForRule) bool {
			port := event.Event.RemotePort()
			portStr := strconv.Itoa(int(port))
			switch check.Op {
			case "in":
				return valueSet[portStr]
			case "not_in":
				return !valueSet[portStr]
			case "=":
				return portStr == check.Values[0]
			}
			return false
		}

	case "fd.rip", "fd.rip.name":
		return func(event *EnrichedEventForRule) bool {
			ip := event.Event.RemoteIP()
			switch check.Op {
			case "in":
				return valueSet[ip]
			case "not_in":
				return !valueSet[ip]
			case "contains":
				return strings.Contains(ip, check.Values[0])
			}
			return false
		}

	case "fd.name":
		switch check.Op {
		case "pmatch":
			return func(event *EnrichedEventForRule) bool {
				path := event.Event.FilePath()
				for _, prefix := range check.Values {
					if strings.HasPrefix(path, prefix) {
						return true
					}
				}
				return false
			}
		case "contains":
			return func(event *EnrichedEventForRule) bool {
				return strings.Contains(event.Event.FilePath(), check.Values[0])
			}
		}

	case "evt.arg.nstype":
		return func(event *EnrichedEventForRule) bool {
			nsType := event.Event.Payload.Escape.NSType
			nsStr := strconv.Itoa(int(nsType))
			switch check.Op {
			case "=":
				return nsStr == check.Values[0]
			case "in":
				return valueSet[nsStr]
			}
			return false
		}

	case "evt.arg.flags":
		return func(event *EnrichedEventForRule) bool {
			flags := event.Event.Payload.File.Flags
			for _, v := range check.Values {
				lowerV := strings.ToLower(v)
				if lowerV == "o_wronly" && flags&1 != 0 {
					return true
				}
				if lowerV == "o_rdwr" && flags&2 != 0 {
					return true
				}
			}
			return false
		}

	case "evt.arg.mode":
		return func(event *EnrichedEventForRule) bool {
			modeFlags := event.Event.Payload.Privilege.ModeFlags
			for _, v := range check.Values {
				if strings.Contains(strings.ToLower(v), "s_isuid") && modeFlags&04000 != 0 {
					return true
				}
				if strings.Contains(strings.ToLower(v), "s_isgid") && modeFlags&02000 != 0 {
					return true
				}
			}
			return false
		}
	}

	// Default: return false to avoid false positives
	return func(event *EnrichedEventForRule) bool { return false }
}
