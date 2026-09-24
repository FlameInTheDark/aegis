package main

import (
	"context"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/connectorapp"
	"github.com/urfave/cli/v3"
)

// v1.25.0: --agent / --scanner run exactly one function; they are mutually
// exclusive; the default (neither flag) follows the connection settings.

func overrideArgs(t *testing.T, args ...string) (*cli.Command, error) {
	t.Helper()
	cmd := &cli.Command{
		Flags: functionFlags(),
		Action: func(_ context.Context, c *cli.Command) error {
			return nil
		},
	}
	err := cmd.Run(context.Background(), append([]string{"aegis-connector"}, args...))
	return cmd, err
}

func TestFunctionOverrideSingleFlags(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"start", "--agent"}, connectorapp.FnAgent},
		{[]string{"start", "--scanner"}, connectorapp.FnScanner},
	} {
		cmd, err := overrideArgs(t, tc.args...)
		if err != nil {
			t.Fatalf("%v: unexpected run error: %v", tc.args, err)
		}
		got, err := functionOverride(cmd)
		if err != nil {
			t.Fatalf("%v: functionOverride: %v", tc.args, err)
		}
		if got != tc.want {
			t.Fatalf("%v: override = %q, want %q", tc.args, got, tc.want)
		}
	}
}

func TestFunctionOverrideDefaultIsEmpty(t *testing.T) {
	cmd, err := overrideArgs(t, "start")
	if err != nil {
		t.Fatal(err)
	}
	got, err := functionOverride(cmd)
	if err != nil || got != "" {
		t.Fatalf("no flags must yield empty override, got %q %v", got, err)
	}
}

func TestFunctionOverrideBothFlagsRejected(t *testing.T) {
	cmd, err := overrideArgs(t, "start", "--agent", "--scanner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := functionOverride(cmd); err == nil {
		t.Fatal("--agent --scanner together must be rejected")
	}
}
