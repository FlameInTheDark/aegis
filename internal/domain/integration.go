package domain

import (
	"encoding/json"
	"time"
)

// Integration kinds (F6 first; F10's cloud connection reuses this table).
const (
	IntegrationGitHub = "github"
	IntegrationJira   = "jira"
	IntegrationAWS    = "aws"
)

// Integration is one per-organization outbound integration. Config holds
// the non-secret settings (GitHub: repo; Jira: site, project, issue type);
// Secret holds the API token and is never serialized — the repo layer
// returns it masked, the same treatment as alert destination secrets.
type Integration struct {
	ID           string          `json:"id"`
	OrgID        string          `json:"organization_id"`
	Kind         string          `json:"kind"`
	Config       json.RawMessage `json:"config,omitempty"`
	Secret       string          `json:"-"`
	CreatedBy    string          `json:"created_by"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	SecretMasked string          `json:"secret_masked,omitempty"`
}

// ValidIntegrationKind reports whether kind is a known integration.
func ValidIntegrationKind(kind string) bool {
	return kind == IntegrationGitHub || kind == IntegrationJira || kind == IntegrationAWS
}

// GitHubConfig is the non-secret GitHub integration settings.
type GitHubConfig struct {
	Repo string `json:"repo"` // "owner/name"
}

// JiraConfig is the non-secret Jira integration settings. Email + API token
// (stored in Secret) form the Basic-Auth pair Jira Cloud expects.
type JiraConfig struct {
	Site      string `json:"site"`       // "https://example.atlassian.net"
	Email     string `json:"email"`      // Atlassian account email
	Project   string `json:"project"`    // project key
	IssueType string `json:"issue_type"` // default "Task"
}

// AWSConfig is the non-secret AWS connector settings (F10). The secret
// access key rides Integration.Secret; the access key id is config.
type AWSConfig struct {
	Region    string `json:"region"`     // "us-east-1"
	AccessKey string `json:"access_key"` // read-only IAM access key id
	SiteID    string `json:"site_id"`    // assets land in this site
}
