// Package handoff pushes findings to external trackers (F6: GitHub Issues
// and Jira in the first slice, one-way). The tracker call can fail and the
// user can see it immediately — replay/attempt history rides the console
// interaction, not a queue, because a handoff is user-initiated and rare.
package handoff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// Client performs tracker API calls. Zero-value fields pick production
// defaults; the base-URL overrides exist for tests.
type Client struct {
	// HTTP defaults to a 15s-timeout client.
	HTTP *http.Client
	// GitHubAPIBase overrides https://api.github.com (tests).
	GitHubAPIBase string
}

// Issue is the result of one create call.
type Issue struct {
	Key   string
	URL   string
	State string // tracker-native ("open"/"closed" for GitHub, status name for Jira)
}

var errNotConfigured = errors.New("tracker integration is not configured")

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// IsClosed reports whether a tracker-native state means the work is done.
func IsClosed(state string) bool {
	s := strings.ToLower(strings.TrimSpace(state))
	return s == "closed" || s == "done" || strings.Contains(s, "resolved") || strings.Contains(s, "closed")
}

// IssueBody renders the finding summary pushed to the tracker: title, CVE,
// asset, evidence and the risk explanation — the content a remediator
// without an Aegis login needs.
func IssueBody(f *domain.Finding, assetName, consoleURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Severity: %s (risk %.0f)\n", f.Severity, f.RiskScore)
	if f.CVEID != "" {
		fmt.Fprintf(&b, "CVE: %s\n", f.CVEID)
	}
	if f.OSVID != "" {
		fmt.Fprintf(&b, "Advisory: %s\n", f.OSVID)
	}
	if assetName != "" {
		fmt.Fprintf(&b, "Asset: %s\n", assetName)
	}
	if f.Product != "" {
		fmt.Fprintf(&b, "Product: %s %s\n", f.Product, f.Version)
	}
	if f.MatchType != "" {
		fmt.Fprintf(&b, "Match: %s (confidence %.2f)\n", f.MatchType, f.Confidence)
	}
	if f.Remediation != "" {
		fmt.Fprintf(&b, "\nRemediation:\n%s\n", f.Remediation)
	}
	if f.Notes != "" {
		fmt.Fprintf(&b, "\nNotes:\n%s\n", f.Notes)
	}
	if consoleURL != "" {
		fmt.Fprintf(&b, "\nOpen in Aegis: %s/#/assets/%s\n", strings.TrimSuffix(consoleURL, "/"), f.AssetID)
	}
	fmt.Fprintf(&b, "\nFirst seen: %s\nLast seen: %s\n", f.FirstSeen.Format(time.RFC3339), f.LastSeen.Format(time.RFC3339))
	return b.String()
}

// Create pushes the finding to the tracker configured for its org and
// returns the external key and URL.
func (c *Client) Create(ctx context.Context, integ *domain.Integration, f *domain.Finding, assetName, consoleURL string) (Issue, error) {
	title := f.Title
	if f.CVEID != "" && !strings.Contains(title, f.CVEID) {
		title = f.CVEID + ": " + title
	}
	body := IssueBody(f, assetName, consoleURL)
	switch integ.Kind {
	case domain.IntegrationGitHub:
		return c.createGitHub(ctx, integ, title, body)
	case domain.IntegrationJira:
		return c.createJira(ctx, integ, title, body)
	}
	return Issue{}, fmt.Errorf("unsupported tracker %q", integ.Kind)
}

// FetchState reads the tracker-native state of a previously created issue.
func (c *Client) FetchState(ctx context.Context, integ *domain.Integration, key string) (string, error) {
	switch integ.Kind {
	case domain.IntegrationGitHub:
		return c.fetchGitHub(ctx, integ, key)
	case domain.IntegrationJira:
		return c.fetchJira(ctx, integ, key)
	}
	return "", fmt.Errorf("unsupported tracker %q", integ.Kind)
}

func (c *Client) createGitHub(ctx context.Context, integ *domain.Integration, title, body string) (Issue, error) {
	if integ.Secret == "" {
		return Issue{}, errNotConfigured
	}
	var cfg domain.GitHubConfig
	if err := json.Unmarshal(integ.Config, &cfg); err != nil || cfg.Repo == "" {
		return Issue{}, errors.New("github config must set repo to \"owner/name\"")
	}
	cfg.Repo = strings.TrimPrefix(cfg.Repo, "/")
	if strings.Count(cfg.Repo, "/") != 1 {
		return Issue{}, errors.New("github repo must look like owner/name")
	}
	payload := map[string]any{"title": title, "body": body, "labels": []string{"aegis"}}
	buf, _ := json.Marshal(payload)
	base := c.GitHubAPIBase
	if base == "" {
		base = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/repos/%s/issues", base, cfg.Repo), bytes.NewReader(buf))
	if err != nil {
		return Issue{}, err
	}
	req.Header.Set("Authorization", "Bearer "+integ.Secret)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	var resp struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
		State   string `json:"state"`
		Message string `json:"message"`
	}
	if err := c.doJSON(req, &resp); err != nil {
		return Issue{}, err
	}
	if resp.Number == 0 {
		return Issue{}, fmt.Errorf("github: %s", resp.Message)
	}
	return Issue{Key: strconv.Itoa(resp.Number), URL: resp.HTMLURL, State: resp.State}, nil
}

func (c *Client) fetchGitHub(ctx context.Context, integ *domain.Integration, key string) (string, error) {
	if integ.Secret == "" {
		return "", errNotConfigured
	}
	var cfg domain.GitHubConfig
	if err := json.Unmarshal(integ.Config, &cfg); err != nil || cfg.Repo == "" {
		return "", errors.New("github config must set repo to \"owner/name\"")
	}
	base := c.GitHubAPIBase
	if base == "" {
		base = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/repos/%s/issues/%s", base, cfg.Repo, url.PathEscape(key)), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+integ.Secret)
	req.Header.Set("Accept", "application/vnd.github+json")
	var resp struct {
		State   string `json:"state"`
		Message string `json:"message"`
	}
	if err := c.doJSON(req, &resp); err != nil {
		return "", err
	}
	if resp.State == "" {
		return "", fmt.Errorf("github: %s", resp.Message)
	}
	return resp.State, nil
}

func (c *Client) createJira(ctx context.Context, integ *domain.Integration, title, body string) (Issue, error) {
	var cfg domain.JiraConfig
	if err := json.Unmarshal(integ.Config, &cfg); err != nil {
		return Issue{}, errors.New("invalid jira config")
	}
	site := strings.TrimSuffix(cfg.Site, "/")
	if site == "" {
		return Issue{}, errors.New("jira site is required")
	}
	if cfg.Project == "" {
		return Issue{}, errors.New("jira project key is required")
	}
	issueType := cfg.IssueType
	if issueType == "" {
		issueType = "Task"
	}
	payload := map[string]any{
		"fields": map[string]any{
			"project":   map[string]any{"key": cfg.Project},
			"summary":   title,
			"issuetype": map[string]any{"name": issueType},
		},
	}
	// Jira Cloud API v3 requires Atlassian Document Format; API v2 accepts
	// plain text, which is what the fixed-field body is.
	payload["fields"].(map[string]any)["description"] = body
	buf, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, site+"/rest/api/2/issue", bytes.NewReader(buf))
	if err != nil {
		return Issue{}, err
	}
	c.setJiraAuth(req, integ)
	req.Header.Set("Content-Type", "application/json")
	var resp struct {
		Key     string `json:"key"`
		ErrMesg string `json:"errorMessages"`
	}
	if err := c.doJSON(req, &resp); err != nil {
		return Issue{}, err
	}
	if resp.Key == "" {
		return Issue{}, fmt.Errorf("jira: %s", resp.ErrMesg)
	}
	return Issue{Key: resp.Key, URL: site + "/browse/" + resp.Key}, nil
}

func (c *Client) fetchJira(ctx context.Context, integ *domain.Integration, key string) (string, error) {
	var cfg domain.JiraConfig
	if err := json.Unmarshal(integ.Config, &cfg); err != nil || cfg.Site == "" {
		return "", errors.New("invalid jira config")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(cfg.Site, "/")+"/rest/api/2/issue/"+url.PathEscape(key)+"?fields=status", nil)
	if err != nil {
		return "", err
	}
	c.setJiraAuth(req, integ)
	var resp struct {
		Fields struct {
			Status struct {
				Name string `json:"name"`
			} `json:"status"`
		} `json:"fields"`
		ErrMesg string `json:"errorMessages"`
	}
	if err := c.doJSON(req, &resp); err != nil {
		return "", err
	}
	if resp.Fields.Status.Name == "" {
		return "", fmt.Errorf("jira: %s", resp.ErrMesg)
	}
	return resp.Fields.Status.Name, nil
}

func (c *Client) setJiraAuth(req *http.Request, integ *domain.Integration) {
	// Jira Cloud: Basic auth with the account email and an API token.
	var cfg domain.JiraConfig
	_ = json.Unmarshal(integ.Config, &cfg)
	req.SetBasicAuth(cfg.Email, integ.Secret)
}

func (c *Client) doJSON(req *http.Request, out any) error {
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("tracker returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}
