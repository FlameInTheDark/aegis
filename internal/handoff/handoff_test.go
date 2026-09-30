package handoff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

func testFinding() *domain.Finding {
	return &domain.Finding{
		ID:          "f-1",
		AssetID:     "a-1",
		CVEID:       "CVE-2026-1234",
		Title:       "OpenSSL too old",
		MatchType:   domain.MatchOSPackage,
		Confidence:  1.0,
		RiskScore:   82,
		Severity:    domain.SeverityHigh,
		Status:      domain.FindingOpen,
		Remediation: "Upgrade openssl to 3.1",
		FirstSeen:   time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:    time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC),
	}
}

func TestCreateGitHubIssue(t *testing.T) {
	var gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		gotBody = string(b)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"number": 42, "html_url": "https://github.com/o/r/issues/42", "state": "open"})
	}))
	defer srv.Close()

	c := &Client{GitHubAPIBase: srv.URL}
	integ := &domain.Integration{
		Kind:   domain.IntegrationGitHub,
		Config: json.RawMessage(`{"repo":"owner/name"}`),
		Secret: "ghpat",
	}
	issue, err := c.Create(context.Background(), integ, testFinding(), "web-01", "https://aegis.example.com")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if issue.Key != "42" || issue.URL == "" || issue.State != "open" {
		t.Fatalf("issue: %+v", issue)
	}
	if gotPath != "/repos/owner/name/issues" {
		t.Fatalf("path: %s", gotPath)
	}
	if gotAuth != "Bearer ghpat" {
		t.Fatalf("auth: %s", gotAuth)
	}
	if !strings.Contains(gotBody, "CVE-2026-1234") || !strings.Contains(gotBody, "web-01") {
		t.Fatalf("body missing content: %s", gotBody)
	}
}

func TestFetchGitHubStateClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/name/issues/42" {
			t.Fatalf("path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"state": "closed"})
	}))
	defer srv.Close()
	c := &Client{GitHubAPIBase: srv.URL}
	integ := &domain.Integration{Kind: domain.IntegrationGitHub, Config: json.RawMessage(`{"repo":"owner/name"}`), Secret: "t"}
	state, err := c.FetchState(context.Background(), integ, "42")
	if err != nil {
		t.Fatalf("FetchState: %v", err)
	}
	if !IsClosed(state) {
		t.Fatalf("state %q should map to closed", state)
	}
}

func TestCreateJiraIssue(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"key": "OPS-7"})
	}))
	defer srv.Close()

	c := &Client{}
	integ := &domain.Integration{
		Kind:   domain.IntegrationJira,
		Config: json.RawMessage(`{"site":"` + srv.URL + `","email":"bot@example.com","project":"OPS","issue_type":"Task"}`),
		Secret: "jiratoken",
	}
	issue, err := c.Create(context.Background(), integ, testFinding(), "web-01", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if issue.Key != "OPS-7" || !strings.HasSuffix(issue.URL, "/browse/OPS-7") {
		t.Fatalf("issue: %+v", issue)
	}
	if gotPath != "/rest/api/2/issue" {
		t.Fatalf("path: %s", gotPath)
	}
	if gotAuth == "" {
		t.Fatal("expected basic auth header")
	}
}

func TestFetchJiraStatusMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"fields": map[string]any{"status": map[string]any{"name": "Done"}}})
	}))
	defer srv.Close()
	c := &Client{}
	integ := &domain.Integration{Kind: domain.IntegrationJira, Config: json.RawMessage(`{"site":"` + srv.URL + `","email":"e@x.com","project":"P"}`), Secret: "t"}
	state, err := c.FetchState(context.Background(), integ, "OPS-7")
	if err != nil {
		t.Fatalf("FetchState: %v", err)
	}
	if !IsClosed(state) {
		t.Fatalf("Done should map to closed, got %q", state)
	}
}

func TestCreateRejectsUnconfigured(t *testing.T) {
	c := &Client{}
	integ := &domain.Integration{Kind: domain.IntegrationGitHub, Config: json.RawMessage(`{}`), Secret: ""}
	if _, err := c.Create(context.Background(), integ, testFinding(), "", ""); err == nil {
		t.Fatal("expected not-configured error")
	}
}

func TestIsClosedStates(t *testing.T) {
	closed := []string{"closed", "Done", "Resolved", "Done", "Closed"}
	open := []string{"open", "In Progress", "To Do", "Reopened", ""}
	for _, s := range closed {
		if !IsClosed(s) {
			t.Fatalf("%q should be closed", s)
		}
	}
	for _, s := range open {
		if IsClosed(s) {
			t.Fatalf("%q should not be closed", s)
		}
	}
}
