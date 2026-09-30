package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// Service syncs AWS account inventory into the asset model (F10).
// Correlation rules match the platform's existing conventions: instance id
// is a strong identifier (0.95), private IP a weak one (0.2); a public
// address sets exposure at creation only, never over an analyst's choice.
type Service struct {
	Assets *pg.AssetRepo
	Ident  *pg.IdentifierRepo
	Log    Logger
	// HTTP lets tests point the EC2 client at a fake endpoint.
	HTTP *http.Client
	// EndpointBase overrides the EC2 endpoint (tests).
	EndpointBase string
}

// Logger is the subset of *slog.Logger the service needs.
type Logger interface {
	Warn(msg string, args ...any)
	Info(msg string, args ...any)
}

// SyncEC2 runs one DescribeInstances sweep and upserts assets for the org.
// The integration config (region, access key id, site) carries the non-secret
// settings; the secret access key rides Integration.Secret.
func (s *Service) SyncEC2(ctx context.Context, orgID string, integ *domain.Integration) (created, updated int, err error) {
	var cfg domain.AWSConfig
	if err := json.Unmarshal(integ.Config, &cfg); err != nil || cfg.Region == "" || cfg.AccessKey == "" {
		return 0, 0, fmt.Errorf("aws config must set region and access_key")
	}
	if cfg.SiteID == "" {
		return 0, 0, fmt.Errorf("aws config must set site_id")
	}
	if integ.Secret == "" {
		return 0, 0, fmt.Errorf("aws secret access key is not configured")
	}
	client := &EC2Client{
		AccessKey:    cfg.AccessKey,
		SecretKey:    integ.Secret,
		Region:       cfg.Region,
		HTTP:         s.HTTP,
		EndpointBase: s.EndpointBase,
	}
	instances, err := client.DescribeInstances(ctx, 5)
	if err != nil {
		return 0, 0, err
	}
	for _, inst := range instances {
		if inst.State == "terminated" {
			continue
		}
		hostname := firstNonEmpty(inst.Name, inst.InstanceID)
		ids, _ := s.Ident.FindByIdentifier(ctx, orgID, "cloud_instance", inst.InstanceID)
		if len(ids) > 0 {
			assetID := ids[0]
			fields := map[string]any{
				"hostname":  hostname,
				"last_seen": time.Now().UTC(),
			}
			if err := s.Assets.Update(ctx, orgID, assetID, fields); err != nil {
				s.Log.Warn("aws asset update failed", "asset", assetID, "err", err)
				continue
			}
			_ = s.Ident.Upsert(ctx, assetID, "ip", orEmpty(inst.PrivateIP), domain.IdentifierWeights["ip"])
			updated++
			continue
		}
		asset := &domain.Asset{
			OrganizationID: orgID,
			SiteID:         cfg.SiteID,
			Hostname:       hostname,
			DeviceType:     domain.DeviceVM,
			OSName:         "aws:" + inst.InstanceTyp,
			Tags:           []string{"cloud:aws", "aws:region:" + cfg.Region},
		}
		if inst.PublicIP != "" {
			asset.Exposure = domain.ExposurePublic
		} else {
			asset.Exposure = domain.ExposureInternal
		}
		if err := s.Assets.Insert(ctx, asset); err != nil {
			s.Log.Warn("aws asset insert failed", "instance", inst.InstanceID, "err", err)
			continue
		}
		_ = s.Ident.Upsert(ctx, asset.ID, "cloud_instance", inst.InstanceID, domain.IdentifierWeights["cloud_instance"])
		if inst.PrivateIP != "" {
			_ = s.Ident.Upsert(ctx, asset.ID, "ip", inst.PrivateIP, domain.IdentifierWeights["ip"])
		}
		if inst.PublicIP != "" {
			_ = s.Ident.Upsert(ctx, asset.ID, "ip", inst.PublicIP, domain.IdentifierWeights["ip"])
		}
		created++
	}
	return created, updated, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func orEmpty(s string) string { return s }
