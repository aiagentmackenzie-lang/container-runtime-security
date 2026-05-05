// Package rules - parser.go
// Parses YAML rule definitions into internal Go structures.
// Compatible with Falco's rule model (lists, macros, rules, exceptions).

package rules

import (
	"fmt"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// ── Parsed YAML Structures ───────────────────────────────────────────

// RuleFile represents the top-level YAML structure of a rules file.
type RuleFile struct {
	Items []RuleFileItem `json:"items" yaml:"items"`
}

// RuleFileItem is a discriminated union: it's either a list, macro, or rule.
type RuleFileItem struct {
	List  *ListDef  `json:"list,omitempty"`
	Macro *MacroDef `json:"macro,omitempty"`
	Rule  *RuleDef  `json:"rule,omitempty"`
}

// ListDef defines a named list of values.
type ListDef struct {
	Name  string   `json:"list" yaml:"list"`
	Items []string `json:"items" yaml:"items"`
}

// MacroDef defines a named condition macro that can be expanded in rules.
type MacroDef struct {
	Name      string `json:"macro" yaml:"macro"`
	Condition string `json:"condition" yaml:"condition"`
}

// RuleDef defines a detection rule.
type RuleDef struct {
	ID         string        `json:"id,omitempty" yaml:"id,omitempty"`
	Name       string        `json:"rule" yaml:"rule"`
	Desc       string        `json:"desc" yaml:"desc"`
	Condition  string        `json:"condition" yaml:"condition"`
	Output     string        `json:"output" yaml:"output"`
	Priority   string        `json:"priority" yaml:"priority"`
	Tags       []string      `json:"tags,omitempty" yaml:"tags,omitempty"`
	Action     string        `json:"action,omitempty" yaml:"action,omitempty"`
	Correlate  *CorrelateDef `json:"correlate,omitempty" yaml:"correlate,omitempty"`
	Exceptions []ExceptionDef `json:"exceptions,omitempty" yaml:"exceptions,omitempty"`
}

// CorrelateDef specifies multi-signal correlation parameters.
type CorrelateDef struct {
	Window  string   `json:"window" yaml:"window"`   // e.g., "5s"
	Signals []string `json:"signals" yaml:"signals"`
	Logic   string   `json:"logic" yaml:"logic"` // "all" or "any"
	GroupBy []string `json:"group_by" yaml:"group_by"`
}

// ExceptionDef defines an exception to a rule.
type ExceptionDef struct {
	Name   string     `json:"name" yaml:"name"`
	Fields []string   `json:"fields" yaml:"fields"`
	Comps  []string   `json:"comps" yaml:"comps"`
	Values [][]string `json:"values" yaml:"values"`
}

// ListValues wraps list values with a name.
type ListValues struct {
	Name  string
	Items []string
}

// ── Parser ────────────────────────────────────────────────────────────

// Parser handles YAML rule file parsing.
type Parser struct {
	lists map[string]ListValues
}

// NewParser creates a new rule parser with the given pre-defined lists.
func NewParser(lists map[string]ListValues) *Parser {
	return &Parser{lists: lists}
}

// ParseYAML parses a YAML rules document and returns rules, macros, and lists.
func (p *Parser) ParseYAML(data []byte) ([]RuleDef, []MacroDef, []ListValues, error) {
	// The YAML format has top-level items that can be lists, macros, or rules.
	// We need to parse them individually since they share no common structure.

	var rules []RuleDef
	var macros []MacroDef
	var lists []ListValues

	// Parse the raw YAML — handle each item type
	rawItems, err := p.parseRawItems(data)
	if err != nil {
		return nil, nil, nil, err
	}

	for _, item := range rawItems {
		switch {
		case item.ListDef != nil:
			lv := ListValues{
				Name:  item.ListDef.Name,
				Items: item.ListDef.Items,
			}
			lists = append(lists, lv)
			p.lists[item.ListDef.Name] = lv

		case item.MacroDef != nil:
			macros = append(macros, *item.MacroDef)

		case item.RuleDef != nil:
			rd := item.RuleDef
			// Assign ID if not present
			if rd.ID == "" {
				rd.ID = sanitizeRuleID(rd.Name)
			}
			// Default action
			if rd.Action == "" {
				rd.Action = ActionAlert
			}
			// Parse correlate window
			if rd.Correlate != nil {
				dur, err := parseDuration(rd.Correlate.Window)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("rule %s: invalid correlate window: %w", rd.Name, err)
				}
				rd.Correlate.Window = dur.String()
				_ = dur // stored as string for now
			}
			rules = append(rules, *rd)
		}
	}

	return rules, macros, lists, nil
}

// rawItem is a helper for discriminated parsing.
type rawItem struct {
	ListDef  *ListDef
	MacroDef *MacroDef
	RuleDef  *RuleDef
}

// parseRawItems attempts to parse YAML into individual items.
func (p *Parser) parseRawItems(data []byte) ([]rawItem, error) {
	var items []rawItem

	// Use a flexible approach: try to parse as array of maps
	var rawArray []map[string]interface{}
	if err := yaml.Unmarshal(data, &rawArray); err == nil {
		for _, m := range rawArray {
			item := p.parseMapToItem(m)
			items = append(items, item)
		}
		return items, nil
	}

	// Try as single document with items key
	var doc struct {
		Items []map[string]interface{} `json:"items" yaml:"items"`
	}
	if err := yaml.Unmarshal(data, &doc); err == nil && len(doc.Items) > 0 {
		for _, m := range doc.Items {
			item := p.parseMapToItem(m)
			items = append(items, item)
		}
		return items, nil
	}

	return nil, fmt.Errorf("failed to parse rule file: unrecognized format")
}

// parseMapToItem converts a raw YAML map into a typed rawItem.
func (p *Parser) parseMapToItem(m map[string]interface{}) rawItem {
	// Check for list
	if name, ok := m["list"].(string); ok {
		if itemsRaw, ok := m["items"]; ok {
			items := toStringSlice(itemsRaw)
			return rawItem{ListDef: &ListDef{Name: name, Items: items}}
		}
	}

	// Check for macro
	if name, ok := m["macro"].(string); ok {
		if cond, ok := m["condition"].(string); ok {
			return rawItem{MacroDef: &MacroDef{Name: name, Condition: cond}}
		}
	}

	// Check for rule
	if name, ok := m["rule"].(string); ok {
		rule := &RuleDef{
			Name: name,
		}
		if desc, ok := m["desc"].(string); ok {
			rule.Desc = desc
		}
		if cond, ok := m["condition"].(string); ok {
			rule.Condition = cond
		}
		if output, ok := m["output"].(string); ok {
			rule.Output = output
		}
		if priority, ok := m["priority"].(string); ok {
			rule.Priority = priority
		}
		if action, ok := m["action"].(string); ok {
			rule.Action = action
		}
		if id, ok := m["id"].(string); ok {
			rule.ID = id
		}
		if tags, ok := m["tags"]; ok {
			rule.Tags = toStringSlice(tags)
		}
		return rawItem{RuleDef: rule}
	}

	return rawItem{}
}

// ── Helpers ───────────────────────────────────────────────────────────

func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

func sanitizeRuleID(name string) string {
	// Convert rule name to a dashed ID
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, "—", "-")
	s = strings.ReplaceAll(s, ",", "")
	s = strings.ReplaceAll(s, "(", "")
	s = strings.ReplaceAll(s, ")", "")
	s = strings.ReplaceAll(s, "/", "-")
	// Remove consecutive dashes
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}

func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "s") {
		return time.ParseDuration(s)
	}
	if strings.HasSuffix(s, "m") {
		return time.ParseDuration(s)
	}
	if strings.HasSuffix(s, "h") {
		return time.ParseDuration(s)
	}
	// Default: seconds
	d, err := time.ParseDuration(s + "s")
	if err == nil {
		return d, nil
	}
	return time.ParseDuration(s)
}