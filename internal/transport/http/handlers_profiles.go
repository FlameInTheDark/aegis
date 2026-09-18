package httpx

import (
	"regexp"
	"strings"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/scanning"
	"github.com/gofiber/fiber/v2"
)

// Custom nmap presets (Settings → Scan presets): org-scoped scan profiles
// persisted in scan_profiles (is_builtin = false). Writes require
// settings:manage; every scan creator can list them.

var presetNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`)

func (a *App) handleListScanProfiles(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	ctx := Context(c)
	builtins := make([]domain.ProfileDefinition, 0, len(domain.Profiles))
	for name, def := range domain.Profiles {
		d := def
		d.Name = name
		d.Builtin = true
		d.ExtraArgs = nil
		builtins = append(builtins, d)
	}
	custom, err := a.svc.Profiles.ListCustom(ctx, claims.OrganizationID)
	if err != nil {
		return Internal("could not list presets")
	}
	return c.JSON(fiber.Map{"builtin": builtins, "custom": custom})
}

type presetRequest struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	TopTCPPorts   int      `json:"top_tcp_ports"`
	FullPortScan  bool     `json:"full_port_scan"`
	ServiceDetect bool     `json:"service_detect"`
	ServiceLite   bool     `json:"service_lite"`
	OSDetect      bool     `json:"os_detect"`
	Traceroute    bool     `json:"traceroute"`
	MaxTargets    int      `json:"max_targets"`
	MaxPacketRate int      `json:"max_packet_rate"`
	ExtraArgs     []string `json:"extra_args"`
}

func (r *presetRequest) sanitize() {
	r.Name = strings.ToLower(strings.TrimSpace(r.Name))
	r.Description = strings.TrimSpace(r.Description)
	for i := range r.ExtraArgs {
		r.ExtraArgs[i] = strings.TrimSpace(r.ExtraArgs[i])
	}
}

func (r *presetRequest) validate() error {
	if !presetNameRe.MatchString(r.Name) {
		return BadRequest("preset name must be 3-32 chars: lowercase letters, digits, dashes")
	}
	if _, builtin := domain.Profiles[domain.ScanProfile(r.Name)]; builtin {
		return BadRequest("this name is reserved by a built-in profile")
	}
	if len(r.Description) > 200 {
		return BadRequest("description too long (max 200)")
	}
	if r.FullPortScan && r.TopTCPPorts > 0 {
		return BadRequest("choose either a top-ports count or a full-range sweep, not both")
	}
	if r.TopTCPPorts < 0 || r.TopTCPPorts > 65535 {
		return BadRequest("top_tcp_ports must be 0..65535")
	}
	if r.MaxTargets < 0 || r.MaxTargets > 262144 {
		return BadRequest("max_targets must be 0..262144")
	}
	if r.MaxPacketRate < 0 || r.MaxPacketRate > 100000 {
		return BadRequest("max_packet_rate must be 0..100000")
	}
	if len(r.ExtraArgs) > 32 {
		return BadRequest("too many extra arguments (max 32 tokens)")
	}
	if err := scanning.ValidateNmapArgs(r.ExtraArgs); err != nil {
		return BadRequest("extra args rejected: " + err.Error())
	}
	return nil
}

func (r *presetRequest) definition() *domain.ProfileDefinition {
	def := &domain.ProfileDefinition{
		Name:          domain.ScanProfile(r.Name),
		Description:   r.Description,
		TopTCPPorts:   r.TopTCPPorts,
		FullPortScan:  r.FullPortScan,
		ServiceDetect: r.ServiceDetect,
		ServiceLite:   r.ServiceLite,
		OSDetect:      r.OSDetect,
		Traceroute:    r.Traceroute,
		MaxTargets:    r.MaxTargets,
		MaxPacketRate: r.MaxPacketRate,
		ExtraArgs:     r.ExtraArgs,
		Builtin:       false,
		// conservative defaults mirroring the built-in baseline
		HostDiscovery: true,
		SafeNSE:       false,
	}
	if def.MaxTargets == 0 {
		def.MaxTargets = 4096
	}
	if def.MaxPacketRate == 0 {
		def.MaxPacketRate = 100
	}
	return def
}

func (a *App) handleCreateScanProfile(c *fiber.Ctx) error {
	if he := a.requirePerm(c, domain.PermSettingsManage); he != nil {
		return he
	}
	var req presetRequest
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid request body")
	}
	req.sanitize()
	if err := req.validate(); err != nil {
		return err
	}
	claims := a.claimsFrom(c)
	def := req.definition()
	if err := a.svc.Profiles.CreateCustom(Context(c), claims.OrganizationID, def); err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "SQLSTATE 23505") {
			return Conflict("a preset with this name already exists")
		}
		return Internal("could not create preset")
	}
	return c.Status(201).JSON(def)
}

func (a *App) handleUpdateScanProfile(c *fiber.Ctx) error {
	if he := a.requirePerm(c, domain.PermSettingsManage); he != nil {
		return he
	}
	var req presetRequest
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid request body")
	}
	req.Name = strings.ToLower(strings.TrimSpace(c.Params("name")))
	req.sanitize()
	if err := req.validate(); err != nil {
		return err
	}
	claims := a.claimsFrom(c)
	def := req.definition()
	if err := a.svc.Profiles.UpdateCustom(Context(c), claims.OrganizationID, def); err != nil {
		return NotFound("preset not found")
	}
	return c.JSON(def)
}

func (a *App) handleDeleteScanProfile(c *fiber.Ctx) error {
	if he := a.requirePerm(c, domain.PermSettingsManage); he != nil {
		return he
	}
	claims := a.claimsFrom(c)
	name := strings.ToLower(strings.TrimSpace(c.Params("name")))
	err := a.svc.Profiles.DeleteCustom(Context(c), claims.OrganizationID, name)
	if err != nil {
		if strings.Contains(err.Error(), "SQLSTATE 23503") || strings.Contains(err.Error(), "violates foreign key") {
			return Conflict("preset is referenced by existing scans and cannot be deleted")
		}
		return NotFound("preset not found")
	}
	return c.SendStatus(204)
}
