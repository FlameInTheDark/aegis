package httpx

import (
	"embed"
	"errors"
	"strings"

	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/FlameInTheDark/aegis/internal/telemetry"
	"github.com/gofiber/fiber/v2"
)

// F11 (sensor setup that finishes in the console): ingest tokens, a test
// ingest that runs the shipped fixture files through the real pipeline
// tagged synthetic, and copy-ready collector snippets.

//go:embed testdata/suricata_eve_sample.jsonl testdata/zeek_conn_sample.jsonl testdata/snort_alert_sample.json
var sensorFixtures embed.FS

// fixtureSources maps the test-ingest source to its shipped sample file.
var fixtureSources = map[string]string{
	"suricata": "testdata/suricata_eve_sample.jsonl",
	"zeek":     "testdata/zeek_conn_sample.jsonl",
	"snort":    "testdata/snort_alert_sample.json",
}

func embeddedFixture(source string) ([]byte, error) {
	path, ok := fixtureSources[source]
	if !ok {
		return nil, errors.New("unknown source (suricata, zeek, snort)")
	}
	return sensorFixtures.ReadFile(path)
}

func (a *App) handleListIngestTokens(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermEventWrite); he != nil {
		return he
	}
	items, err := a.svc.IngestTokens.List(Context(c), claims.OrganizationID)
	if err != nil {
		return Internal("ingest token list failed")
	}
	return c.JSON(fiber.Map{"items": items})
}

func (a *App) handleCreateIngestToken(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermEventWrite); he != nil {
		return he
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid body")
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 128 {
		return BadRequest("name must be 1-128 characters")
	}
	plaintext, err := auth.GenerateToken(ingestTokenPrefix)
	if err != nil {
		return Internal("token generation failed")
	}
	t := &pg.IngestToken{
		OrgID:     claims.OrganizationID,
		Name:      req.Name,
		Prefix:    plaintext[:12] + "…",
		CreatedBy: claims.Subject,
	}
	if err := a.svc.IngestTokens.Create(Context(c), t, plaintext); err != nil {
		return Internal("ingest token create failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "event.ingest_token_created", "ingest-token:"+t.ID, c.IP(), "", "success",
		map[string]any{"name": req.Name})
	// The plaintext is returned exactly once and never stored — only the
	// SHA-256 hash lands in the database.
	return c.Status(201).JSON(fiber.Map{"token": t, "token_plain": plaintext})
}

func (a *App) handleRevokeIngestToken(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermEventWrite); he != nil {
		return he
	}
	if err := a.svc.IngestTokens.Revoke(Context(c), claims.OrganizationID, c.Params("id")); err != nil {
		return NotFound("ingest token not found")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "event.ingest_token_revoked", "ingest-token:"+c.Params("id"), c.IP(), "", "success", nil)
	return c.SendStatus(204)
}

// handleTestIngest pushes one shipped fixture through the real pipeline
// tagged synthetic, so an operator can watch the Events page light up
// before a real sensor is ever connected.
func (a *App) handleTestIngest(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermEventWrite); he != nil {
		return he
	}
	var req struct {
		Source string `json:"source"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid body")
	}
	fixture, err := embeddedFixture(req.Source)
	if err != nil {
		return BadRequest(err.Error())
	}
	se := telemetry.SubjectEvent{
		TenantID:  claims.OrganizationID,
		SensorID:  "console-test",
		Source:    req.Source,
		Raw:       fixture,
		Synthetic: true, // demo mode's honesty rule, applied to events
	}
	accepted, err := a.svc.Ingestor.HTTPIngest(Context(c), se)
	if err != nil {
		return BadRequest(err.Error())
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "event.test_ingested", "events", c.IP(), "", "success",
		map[string]any{"source": req.Source, "accepted": accepted})
	return c.Status(202).JSON(fiber.Map{"accepted": accepted, "synthetic": true})
}

// handleIngestTokenEvent is the machine endpoint sensors use with a token
// (POST /ingest/events?source=...). Body: raw JSON object or JSONL.
func (a *App) handleIngestTokenEvent(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if len(c.Body()) == 0 {
		return BadRequest("payload required")
	}
	source := c.Query("source")
	if source == "" {
		source = "suricata"
	}
	se := telemetry.SubjectEvent{
		TenantID: claims.OrganizationID,
		Source:   source,
		Raw:      c.Body(),
	}
	accepted, err := a.svc.Ingestor.HTTPIngest(Context(c), se)
	if err != nil {
		return BadRequest(err.Error())
	}
	return c.Status(202).JSON(fiber.Map{"accepted": accepted})
}
