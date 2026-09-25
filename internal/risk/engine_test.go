package risk

import (
	"strings"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

func TestKEVDominatesRisk(t *testing.T) {
	base := Evaluate(Inputs{HasCVSS: true, CVSSScore: 9.8, Criticality: domain.CriticalityMedium}, Default())
	kev := Evaluate(Inputs{HasCVSS: true, CVSSScore: 9.8, KnownExploited: true, Criticality: domain.CriticalityMedium}, Default())
	if kev.Score <= base.Score {
		t.Fatalf("KEV must raise the score: base=%.1f kev=%.1f", base.Score, kev.Score)
	}
	if kev.Severity != domain.SeverityCritical && kev.Severity != domain.SeverityHigh {
		t.Fatalf("KEV+critical CVSS must reach at least high severity, got %s", kev.Severity)
	}
}

func TestRiskIsNotJustCVSS(t *testing.T) {
	// Same CVSS, different environment => different risk.
	internal := Evaluate(Inputs{HasCVSS: true, CVSSScore: 7.5, Criticality: domain.CriticalityLow}, Default())
	public := Evaluate(Inputs{HasCVSS: true, CVSSScore: 7.5, InternetExposed: true, Criticality: domain.CriticalityCritical}, Default())
	if public.Score <= internal.Score {
		t.Fatalf("internet-exposed critical asset must score higher")
	}
}

func TestExplanationIsPresent(t *testing.T) {
	r := Evaluate(Inputs{HasCVSS: true, CVSSScore: 9.8, KnownExploited: true, InternetExposed: true, Criticality: domain.CriticalityCritical}, Default())
	expl := Explain(r)
	if !strings.Contains(expl, "KEV") || !strings.Contains(expl, "Internet") {
		t.Fatalf("explanation must cite key factors: %s", expl)
	}
}

func TestCompensatingControlsReduceScore(t *testing.T) {
	plain := Evaluate(Inputs{HasCVSS: true, CVSSScore: 8.0}, Default())
	controlled := Evaluate(Inputs{HasCVSS: true, CVSSScore: 8.0, CompensatingControls: []string{"waf", "allowlist", "segmentation"}}, Default())
	if controlled.Score >= plain.Score {
		t.Fatalf("controls must reduce score: %.1f vs %.1f", controlled.Score, plain.Score)
	}
}

func TestSeverityBands(t *testing.T) {
	if SeverityFromScore(95) != domain.SeverityCritical {
		t.Fatal(">=80 must be critical")
	}
	if SeverityFromScore(70) != domain.SeverityHigh {
		t.Fatal("60-79 must be high")
	}
	if SeverityFromScore(50) != domain.SeverityMedium {
		t.Fatal("35-59 must be medium")
	}
	if SeverityFromScore(20) != domain.SeverityLow {
		t.Fatal("15-34 must be low")
	}
	if SeverityFromScore(5) != domain.SeverityInfo {
		t.Fatal("<15 must be informational")
	}
}

func TestReliefFactorsAppearInExplanation(t *testing.T) {
	// Relief used to be subtracted from the score while the factor builder
	// silently dropped every non-positive point, hiding WHY the score was
	// reduced from the transparent explanation and the UI breakdown.
	negative := func(r Result, name string) bool {
		for _, f := range r.Factors {
			if f.Name == name && f.Contribution < 0 {
				return true
			}
		}
		return false
	}
	segmented := Evaluate(Inputs{
		HasCVSS:              true,
		CVSSScore:            8.0,
		InternetExposed:      true,
		Segmented:            true,
		CompensatingControls: []string{"waf", "allowlist", "segmentation"},
	}, Default())
	if !negative(segmented, "compensating_controls") || !negative(segmented, "segmented") {
		t.Fatalf("relief factors must appear with negative contributions: %+v", segmented.Factors)
	}
	// Endpoint-agent relief requires a non-internet-exposed asset by design.
	endpoint := Evaluate(Inputs{HasCVSS: true, CVSSScore: 8.0, HasEndpointAgent: true}, Default())
	if !negative(endpoint, "endpoint_visibility") {
		t.Fatalf("endpoint_visibility relief must appear: %+v", endpoint.Factors)
	}
	expl := Explain(segmented)
	if !strings.Contains(strings.ToLower(expl), "compensating") {
		t.Fatalf("explanation must cite compensating controls: %s", expl)
	}
}
