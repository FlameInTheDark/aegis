package domain

import (
	"errors"
	"testing"
)

func TestParentOverrideCycle(t *testing.T) {
	// chain: A -> B -> C (A's parent is B, B's parent is C, C has none)
	overrides := map[string]string{"A": "B", "B": "C"}
	lookup := func(id string) (*string, error) {
		if p, ok := overrides[id]; ok {
			return &p, nil
		}
		return nil, nil
	}

	cases := []struct {
		name     string
		self     string
		proposed string
		cycle    bool
		wantErr  bool
	}{
		{"fresh parent without chain", "A", "X", false, false},
		{"re-affirm the same parent is not a cycle", "A", "B", false, false}, // A->B stands, B->C: a straight chain
		{"proposed parent sits below self", "B", "A", true, false},           // A->B already; B->A would close A<->B
		{"deep cycle through chain", "C", "A", true, false},                  // C->A would close C->A->B->C
		{"self parent", "A", "A", true, false},
		{"unrelated subtree", "C", "X", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParentOverrideCycle(lookup, tc.self, tc.proposed)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.cycle {
				t.Fatalf("cycle = %v, want %v", got, tc.cycle)
			}
		})
	}
}

func TestParentOverrideCycleLookupError(t *testing.T) {
	boom := errors.New("db down")
	_, err := ParentOverrideCycle(func(string) (*string, error) { return nil, boom }, "A", "B")
	if !errors.Is(err, boom) {
		t.Fatalf("lookup error must propagate, got %v", err)
	}
}

func TestParentOverrideCycleExcessiveChain(t *testing.T) {
	// a corrupt loop that never reaches self and never terminates
	overrides := map[string]string{}
	for i := 0; i < maxOverrideChain+2; i++ {
		overrides[string(rune('a'+i))] = string(rune('a' + i + 1))
	}
	lookup := func(id string) (*string, error) {
		if p, ok := overrides[id]; ok {
			return &p, nil
		}
		return nil, nil
	}
	if _, err := ParentOverrideCycle(lookup, "ZZ", "a"); err == nil {
		t.Fatal("excessive chain must error, not walk forever")
	}
}
