package alerting

import (
	"fmt"
	"regexp"
	"strings"
)

// The condition DSL (plan §5.5): bounded, typed boolean expressions over
// event/metric fields. Only the operators below exist; unknown keys, deep
// nesting, huge value lists, arbitrary regex and any form of code are
// rejected at validation time — the server is the canonical validator and
// the editor sends exactly this shape.

// maxDepth bounds nested boolean groups; maxChildren bounds list sizes.
const (
	maxDepth    = 3
	maxChildren = 20
	maxValueLen = 256
	maxFieldLen = 64
	maxRegexLen = 128
)

// Operators.
const (
	OpEq         = "eq"
	OpNeq        = "neq"
	OpIn         = "in"
	OpNotIn      = "not_in"
	OpGt         = "gt"
	OpGte        = "gte"
	OpLt         = "lt"
	OpLte        = "lte"
	OpContains   = "contains"
	OpStartsWith = "starts_with"
	OpEndsWith   = "ends_with"
	OpExists     = "exists"
	OpRegex      = "regex"
)

// Operators is the closed operator set.
var Operators = []string{OpEq, OpNeq, OpIn, OpNotIn, OpGt, OpGte, OpLt, OpLte,
	OpContains, OpStartsWith, OpEndsWith, OpExists, OpRegex}

// numericOps compare numbers; stringOps compare strings.
var numericOps = map[string]bool{OpGt: true, OpGte: true, OpLt: true, OpLte: true}

// Condition is one typed condition or a boolean group.
type Condition struct {
	// Leaf form.
	Field string `json:"field,omitempty"`
	Op    string `json:"op,omitempty"`
	Value any    `json:"value,omitempty"`
	// Group form (exactly one of all/any/not is meaningful per node).
	All []Condition `json:"all,omitempty"`
	Any []Condition `json:"any,omitempty"`
	Not *Condition  `json:"not,omitempty"`
}

// Validate checks structure, operators, sizes and regex compilability.
func (c *Condition) Validate(depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("conditions: nesting deeper than %d is not allowed", maxDepth)
	}
	groups := 0
	if len(c.All) > 0 {
		groups++
	}
	if len(c.Any) > 0 {
		groups++
	}
	if c.Not != nil {
		groups++
	}
	if groups > 1 {
		return fmt.Errorf("conditions: a node must use only one of all/any/not")
	}
	if groups == 1 {
		children := c.All
		if len(c.Any) > 0 {
			children = c.Any
		}
		if len(children) > maxChildren {
			return fmt.Errorf("conditions: more than %d conditions in a group", maxChildren)
		}
		for i := range children {
			if err := children[i].Validate(depth + 1); err != nil {
				return err
			}
		}
		if c.Not != nil {
			return c.Not.Validate(depth + 1)
		}
		return nil
	}
	// Leaf.
	if c.Field == "" || len(c.Field) > maxFieldLen {
		return fmt.Errorf("conditions: field must be 1-%d characters", maxFieldLen)
	}
	if !strings.ContainsFunc(c.Field, func(r rune) bool { return r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' }) {
		return fmt.Errorf("conditions: field %q has unsupported characters", c.Field)
	}
	known := false
	for _, op := range Operators {
		if c.Op == op {
			known = true
			break
		}
	}
	if !known {
		return fmt.Errorf("conditions: unknown operator %q", c.Op)
	}
	switch c.Op {
	case OpIn, OpNotIn:
		vals, ok := c.Value.([]any)
		if !ok || len(vals) == 0 || len(vals) > maxChildren {
			return fmt.Errorf("conditions: %s needs 1-%d values", c.Op, maxChildren)
		}
	case OpExists:
		// no value needed
	case OpRegex:
		pat, ok := c.Value.(string)
		if !ok || pat == "" {
			return fmt.Errorf("conditions: regex needs a pattern string")
		}
		if len(pat) > maxRegexLen {
			return fmt.Errorf("conditions: regex pattern longer than %d characters", maxRegexLen)
		}
		if _, err := regexp.Compile(pat); err != nil {
			return fmt.Errorf("conditions: invalid regex: %v", err)
		}
	default:
		if err := validateScalar(c.Value); err != nil {
			return fmt.Errorf("conditions: field %q: %w", c.Field, err)
		}
	}
	return nil
}

func validateScalar(v any) error {
	switch x := v.(type) {
	case nil, bool, float64, int, string:
		if s, ok := x.(string); ok && len(s) > maxValueLen {
			return fmt.Errorf("value longer than %d characters", maxValueLen)
		}
		return nil
	default:
		return fmt.Errorf("unsupported value type %T", v)
	}
}

// Evaluate applies the condition to a flat data map. Missing fields make
// comparisons false (except exists, which is precisely about presence) —
// a condition can only fire on real evidence.
func (c *Condition) Evaluate(data map[string]any) bool {
	if len(c.All) > 0 {
		for i := range c.All {
			if !c.All[i].Evaluate(data) {
				return false
			}
		}
		return true
	}
	if len(c.Any) > 0 {
		for i := range c.Any {
			if c.Any[i].Evaluate(data) {
				return true
			}
		}
		return false
	}
	if c.Not != nil {
		return !c.Not.Evaluate(data)
	}
	raw, present := lookupPath(data, c.Field)
	switch c.Op {
	case OpExists:
		return present
	case OpIn, OpNotIn:
		vals, ok := c.Value.([]any)
		if !ok {
			return false
		}
		found := false
		for _, v := range vals {
			if scalarEqual(raw, v) {
				found = true
				break
			}
		}
		if c.Op == OpIn {
			return found
		}
		return present && !found
	case OpRegex:
		pat, _ := c.Value.(string)
		re, err := regexp.Compile(pat)
		if err != nil {
			return false
		}
		s, ok := raw.(string)
		return ok && re.MatchString(s)
	}
	switch c.Op {
	case OpEq:
		return scalarEqual(raw, c.Value)
	case OpNeq:
		return present && !scalarEqual(raw, c.Value)
	case OpContains:
		return strings.Contains(asString(raw), asString(c.Value))
	case OpStartsWith:
		return strings.HasPrefix(asString(raw), asString(c.Value))
	case OpEndsWith:
		return strings.HasSuffix(asString(raw), asString(c.Value))
	}
	// Numeric comparisons.
	num, ok := asFloat(raw)
	if !ok {
		return false
	}
	thr, ok := asFloat(c.Value)
	if !ok {
		return false
	}
	switch c.Op {
	case OpGt:
		return num > thr
	case OpGte:
		return num >= thr
	case OpLt:
		return num < thr
	case OpLte:
		return num <= thr
	}
	return false
}

// lookupPath resolves "a.b.c" against nested maps, returning the leaf and
// whether it exists at all.
func lookupPath(data map[string]any, path string) (any, bool) {
	if data == nil {
		return nil, false
	}
	parts := strings.Split(path, ".")
	var cur any = data
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func scalarEqual(a, b any) bool {
	if af, ok := asFloat(a); ok {
		if bf, ok2 := asFloat(b); ok2 {
			return af == bf
		}
		return false
	}
	if as, ok := a.(string); ok {
		bs, ok2 := b.(string)
		return ok2 && as == bs
	}
	ab, ok := a.(bool)
	if !ok {
		return false
	}
	bb, ok2 := b.(bool)
	return ok2 && ab == bb
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprintf("%g", x)
	case bool:
		return fmt.Sprintf("%t", x)
	default:
		return ""
	}
}

func asFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case string:
		var f float64
		if _, err := fmt.Sscanf(strings.TrimSpace(x), "%g", &f); err == nil {
			return f, true
		}
		return 0, false
	default:
		return 0, false
	}
}

// CompileSummary renders a human-readable one-line summary of a condition
// tree (used by the editor's Review step and alert snapshots).
func (c *Condition) CompileSummary() string {
	if c == nil {
		return ""
	}
	if len(c.All) > 0 {
		parts := make([]string, 0, len(c.All))
		for i := range c.All {
			parts = append(parts, c.All[i].CompileSummary())
		}
		return "(" + strings.Join(parts, " and ") + ")"
	}
	if len(c.Any) > 0 {
		parts := make([]string, 0, len(c.Any))
		for i := range c.Any {
			parts = append(parts, c.Any[i].CompileSummary())
		}
		return "(" + strings.Join(parts, " or ") + ")"
	}
	if c.Not != nil {
		return "not " + c.Not.CompileSummary()
	}
	return fmt.Sprintf("%s %s %s", humanField(c.Field), humanOp(c.Op), humanValue(c.Value))
}

func humanField(f string) string { return strings.ReplaceAll(f, "_", " ") }

func humanOp(op string) string {
	switch op {
	case OpEq:
		return "is"
	case OpNeq:
		return "is not"
	case OpIn:
		return "is one of"
	case OpNotIn:
		return "is none of"
	case OpGt:
		return "above"
	case OpGte:
		return "at or above"
	case OpLt:
		return "below"
	case OpLte:
		return "at or below"
	case OpContains:
		return "contains"
	case OpStartsWith:
		return "starts with"
	case OpEndsWith:
		return "ends with"
	case OpExists:
		return "exists"
	case OpRegex:
		return "matches"
	}
	return op
}

func humanValue(v any) string {
	switch x := v.(type) {
	case []any:
		parts := make([]string, 0, len(x))
		for _, item := range x {
			parts = append(parts, asString(item))
		}
		return strings.Join(parts, ", ")
	default:
		return asString(v)
	}
}
