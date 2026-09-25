// Package risk implements the configurable environmental risk engine
// . Risk is never equal to CVSS alone; it blends technical
// severity, exploitation likelihood, environmental exposure and business
// impact into an explainable 0-100 score. Every score carries a human
// readable explanation ("Risk is high because ...").
package risk

import (
	"fmt"
	"sort"
	"strings"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// Inputs bundles every signal the engine considers for one finding.
type Inputs struct {
	// Technical severity from source data.
	CVSSScore float64 // best available CVSS (v3 > v4 preference handled by caller)
	HasCVSS   bool

	// Exploitation likelihood.
	EPSS           float64 // 0..1 probability, FIRST daily snapshot
	KnownExploited bool    // CISA KEV

	// Environmental exposure.
	InternetExposed      bool
	AdminService         bool     // management/admin port exposed
	Unencrypted          bool     // cleartext protocol
	Segmented            bool     // asset sits in a segmented VLAN with limited reachability
	ReachableFromN       int      // number of other segments that can reach the asset
	HasEndpointAgent     bool     // endpoint protection/visibility present
	CompensatingControls []string // e.g. "waf", "allowlist"

	// Business importance.
	Criticality domain.Criticality // low | medium | high | critical
	AssetRisk   float64            // existing asset risk score (0-100)

	// Age.
	DaysOpen int // vulnerability age in days
}

// Factor is one scored component with its contribution and human reason.
type Factor struct {
	Name         string  `json:"name"`
	Contribution float64 `json:"contribution"` // points added to 0-100
	Reason       string  `json:"reason"`
}

// Result is the explainable output of the engine.
type Result struct {
	Score                 float64         `json:"score"` // 0-100
	Severity              domain.Severity `json:"severity"`
	Factors               []Factor        `json:"factors"`
	TechnicalSeverity     float64         `json:"technical_severity"`
	ExploitLikelihood     float64         `json:"exploit_likelihood"`
	EnvironmentalExposure float64         `json:"environmental_exposure"`
	BusinessImpact        float64         `json:"business_impact"`
}

// Weights are transparent, configurable multipliers. They are exported so a
// future settings UI can expose them without changing the engine contract.
type Weights struct {
	CVSSMax       float64 // max contribution from CVSS
	KEVBoost      float64 // flat add when KEV
	EPSSMax       float64 // max add at EPSS=1.0
	ExposureMax   float64
	BusinessMax   float64
	AgeMax        float64
	ControlRelief float64 // max total relief from compensating controls
}

// Default is the baseline weight set. Sum of maxima is >= 100 so signals
// do not all have to fire to reach the top of the scale.
func Default() Weights {
	return Weights{CVSSMax: 40, KEVBoost: 20, EPSSMax: 15, ExposureMax: 25, BusinessMax: 15, AgeMax: 5, ControlRelief: 15}
}

// Evaluate scores one finding context. The output always explains itself.
func Evaluate(in Inputs, w Weights) Result {
	if w.CVSSMax == 0 {
		w = Default()
	}
	var r Result
	add := func(name string, pts float64, format string, args ...any) {
		// Zero means "no signal, no factor". Negative contributions are
		// real: compensating controls and segmentation reduce the score and
		// the explanation must show why, otherwise the transparent factor
		// breakdown silently hides every score reduction.
		if pts == 0 {
			return
		}
		r.Factors = append(r.Factors, Factor{Name: name, Contribution: round1(pts), Reason: fmt.Sprintf(format, args...)})
	}

	// 1. Technical severity (CVSS-driven, capped).
	cvssPts := 0.0
	if in.HasCVSS {
		cvssPts = in.CVSSScore / 10.0 * w.CVSSMax
	}
	r.TechnicalSeverity = round1(cvssPts)
	if in.HasCVSS {
		if in.CVSSScore >= 9 {
			add("critical_cvss", cvssPts, "Critical CVSS %.1f indicates severe technical impact", in.CVSSScore)
		} else {
			add("cvss", cvssPts, "CVSS %.1f contributes to technical severity", in.CVSSScore)
		}
	}

	// 2. Exploitation likelihood (KEV + EPSS are independent signals).
	exploit := 0.0
	if in.KnownExploited {
		exploit += w.KEVBoost
		add("known_exploited", w.KEVBoost, "Listed in CISA KEV: exploitation observed in the wild")
	}
	if in.EPSS > 0 {
		p := in.EPSS * w.EPSSMax
		exploit += p
		add("epss", p, "EPSS %.0f%% exploitation probability in the next 30 days", in.EPSS*100)
	}
	r.ExploitLikelihood = round1(exploit)

	// 3. Environmental exposure.
	exposure := 0.0
	if in.InternetExposed {
		exposure += w.ExposureMax * 0.7
		add("internet_exposed", w.ExposureMax*0.7, "Service is reachable from the Internet")
	} else if in.ReachableFromN > 0 {
		p := w.ExposureMax * 0.3 * clamp(float64(in.ReachableFromN)/4, 0, 1)
		exposure += p
		add("segment_reachability", p, "Reachable from %d other network segments", in.ReachableFromN)
	}
	if in.AdminService {
		p := w.ExposureMax * 0.3
		exposure += p
		add("admin_exposed", p, "Administrative/management interface exposed to the network")
	}
	if in.Unencrypted {
		p := w.ExposureMax * 0.1
		exposure += p
		add("unencrypted", p, "Service transmits cleartext traffic")
	}
	if in.Segmented {
		p := exposure * 0.2
		exposure -= p
		add("segmented", -p, "Asset is in a segmented network (exposure reduced by %.1f points)", round1(p))
	}
	r.EnvironmentalExposure = round1(exposure)

	// 4. Business impact.
	biz := 0.0
	switch in.Criticality {
	case domain.CriticalityCritical:
		biz = w.BusinessMax
		add("critical_asset", biz, "Asset is marked business-critical")
	case domain.CriticalityHigh:
		biz = w.BusinessMax * 0.6
		add("high_value_asset", biz, "Asset is marked high value")
	case domain.CriticalityMedium:
		biz = w.BusinessMax * 0.25
	}
	if in.AssetRisk > 0 {
		biz += (in.AssetRisk / 100) * w.BusinessMax * 0.2
	}
	r.BusinessImpact = round1(biz)

	// 5. Age pressure.
	if in.DaysOpen > 30 {
		p := clamp(float64(in.DaysOpen)/180, 0, 1) * w.AgeMax
		add("age", p, "Vulnerability open for %d days without remediation", in.DaysOpen)
	}

	// 6. Compensating controls reduce the total.
	total := r.TechnicalSeverity + r.ExploitLikelihood + r.EnvironmentalExposure + r.BusinessImpact
	relief := 0.0
	if len(in.CompensatingControls) > 0 {
		relief = clamp(float64(len(in.CompensatingControls))/3, 0, 1) * w.ControlRelief
		add("compensating_controls", -relief, "Compensating controls present: %s", strings.Join(in.CompensatingControls, ", "))
	}
	if in.HasEndpointAgent && !in.InternetExposed {
		p := w.ControlRelief * 0.2
		relief += p
		add("endpoint_visibility", -p, "Endpoint agent provides visibility and control on the asset")
	}
	total -= relief

	r.Score = round1(clamp(total, 0, 100))
	r.Severity = SeverityFromScore(r.Score)
	sort.SliceStable(r.Factors, func(i, j int) bool { return r.Factors[i].Contribution > r.Factors[j].Contribution })
	return r
}

// SeverityFromScore maps the 0-100 risk scale onto the five label levels
// . Labels are always paired with numbers in the UI.
func SeverityFromScore(s float64) domain.Severity {
	switch {
	case s >= 80:
		return domain.SeverityCritical
	case s >= 60:
		return domain.SeverityHigh
	case s >= 35:
		return domain.SeverityMedium
	case s >= 15:
		return domain.SeverityLow
	default:
		return domain.SeverityInfo
	}
}

// Explain renders the transparent one-paragraph explanation required by.
func Explain(r Result) string {
	if len(r.Factors) == 0 {
		return fmt.Sprintf("Risk %.0f: minimal signals present.", r.Score)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Risk is %s (%.0f/100) because", strings.ToLower(labelFor(r.Severity)), r.Score)
	n := 0
	for _, f := range r.Factors {
		if f.Contribution <= 0 {
			continue
		}
		if n > 0 {
			if n == countPos(r.Factors)-1 {
				b.WriteString(" and")
			} else {
				b.WriteString(",")
			}
		}
		b.WriteString(" " + f.Reason)
		n++
		if n >= 4 {
			break
		}
	}
	// Score reductions are part of the explanation too: compensating
	// controls and segmentation reduce the number the reader sees, so the
	// paragraph must mention them instead of only citing the raises.
	var relief []string
	for _, f := range r.Factors {
		if f.Contribution < 0 {
			relief = append(relief, f.Reason)
		}
	}
	switch len(relief) {
	case 0:
	case 1:
		b.WriteString("; offset by " + relief[0])
	default:
		b.WriteString("; offset by " + strings.Join(relief[:len(relief)-1], ", ") +
			" and " + relief[len(relief)-1])
	}
	b.WriteString(".")
	return b.String()
}

func labelFor(s domain.Severity) string {
	switch s {
	case domain.SeverityCritical:
		return "Critical"
	case domain.SeverityHigh:
		return "High"
	case domain.SeverityMedium:
		return "Moderate"
	case domain.SeverityLow:
		return "Low"
	default:
		return "Minimal"
	}
}

func countPos(fs []Factor) int {
	n := 0
	for _, f := range fs {
		if f.Contribution > 0 {
			n++
		}
	}
	return n
}
func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }
