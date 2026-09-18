// Package organizations implements org/site/network lifecycle and the
// first-run bootstrap flow (spec §8, §159/§160).
package organizations

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// Service wires tenancy repos together.
type Service struct {
	Orgs        *pg.OrgRepo
	Users       *pg.UserRepo
	Memberships *pg.MembershipRepo
	Sites       *pg.SiteRepo
	Networks    *pg.NetworkRepo
	Log         *slog.Logger
}

// BootstrapResult describes the created first-run data.
type BootstrapResult struct {
	Organization *domain.Organization
	User         *domain.User
	Site         *domain.Site
}

// Bootstrap creates the initial organization, admin user and default site
// when the installation is empty (spec §160 first run; credentials come
// from configuration, never hardcoded).
func (s *Service) Bootstrap(ctx context.Context, orgName, email, name, passwordHash string) (*BootstrapResult, error) {
	existing, err := s.Users.ByEmail(ctx, email)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("bootstrap user already exists")
	}
	org, err := s.Orgs.Create(ctx, orgName, slugify(orgName))
	if err != nil {
		return nil, err
	}
	user, err := s.Users.Create(ctx, email, name, passwordHash)
	if err != nil {
		return nil, err
	}
	if err := s.Memberships.Add(ctx, user.ID, org.ID, domain.RoleOwner); err != nil {
		return nil, err
	}
	site := &domain.Site{
		ID: ids.New(), OrganizationID: org.ID, Name: "Default Site",
		SiteType: "lab", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := s.Sites.Create(ctx, site); err != nil {
		return nil, err
	}
	s.Log.Info("bootstrap complete", "org", org.ID, "user", user.ID, "site", site.ID)
	return &BootstrapResult{Organization: org, User: user, Site: site}, nil
}

// CreateSite validates and persists a site.
func (s *Service) CreateSite(ctx context.Context, orgID, name, siteType, description string) (*domain.Site, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("site name is required")
	}
	validTypes := map[string]bool{"hq": true, "datacenter": true, "cloud": true, "branch": true, "home": true, "lab": true}
	if siteType == "" {
		siteType = "lab"
	}
	if !validTypes[siteType] {
		return nil, fmt.Errorf("invalid site type %q", siteType)
	}
	site := &domain.Site{
		ID: ids.New(), OrganizationID: orgID, Name: name,
		SiteType: siteType, Description: description,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := s.Sites.Create(ctx, site); err != nil {
		return nil, err
	}
	return site, nil
}

// CreateNetwork validates a CIDR within a site.
func (s *Service) CreateNetwork(ctx context.Context, orgID, siteID, cidr, name, gateway string, vlanID *int) (*domain.Network, error) {
	cidr = strings.TrimSpace(cidr)
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return nil, fmt.Errorf("network must be a valid CIDR (got %q)", cidr)
	}
	gateway = strings.TrimSpace(gateway)
	if gateway != "" {
		if ip := net.ParseIP(gateway); ip == nil {
			return nil, fmt.Errorf("gateway must be a valid IP (got %q)", gateway)
		}
	}
	net := &domain.Network{
		ID: ids.New(), SiteID: siteID, OrganizationID: orgID,
		CIDR: cidr, Name: name, Gateway: gateway, VLANID: vlanID,
		Exposure: domain.ExposureInternal, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := s.Networks.Create(ctx, net); err != nil {
		return nil, err
	}
	return net, nil
}

// slugify produces an org slug from its name.
func slugify(name string) string {
	var b strings.Builder
	last := byte('-')
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9':
			b.WriteByte(c)
			last = c
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c - 'A' + 'a')
			last = c - 'A' + 'a'
		default:
			if last != '-' {
				b.WriteByte('-')
				last = '-'
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// CreateOrg persists a new organization and grants the creator owner role.
func (s *Service) CreateOrg(ctx context.Context, name, creatorUserID string) (*domain.Organization, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("organization name is required")
	}
	org, err := s.Orgs.Create(ctx, name, slugify(name))
	if err != nil {
		return nil, err
	}
	if creatorUserID != "" {
		_ = s.Memberships.Add(ctx, creatorUserID, org.ID, domain.RoleOwner)
	}
	s.Log.Info("organization created", "org", org.ID, "by", creatorUserID)
	return org, nil
}

// RenameOrg updates the organization's display name. Only owners/admins
// reach this through the handler's org:manage permission check.
func (s *Service) Rename(ctx context.Context, orgID, name string) (*domain.Organization, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("organization name is required")
	}
	org, err := s.Orgs.Rename(ctx, orgID, name)
	if err != nil {
		return nil, err
	}
	s.Log.Info("organization renamed", "org", org.ID, "by", "api")
	return org, nil
}
