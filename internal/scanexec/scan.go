package scanexec

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	"github.com/FlameInTheDark/aegis/internal/scanner"
)

// RunScan executes the phased pipeline: discover -> ports ->
// fingerprint -> OS -> topology trace.
func (e *Executor) RunScan(ctx context.Context, scan *domain.Scan, scannerID string) error {
	if scan.Config == nil {
		scan.Config = &domain.ScanConfig{Profile: scan.Profile, MaxRate: 100, TimeoutSecs: 30, Engine: e.Engine.Name()}
	}
	// Resolve the profile definition: built-ins come from the static
	// registry, custom nmap presets from the scan_profiles table (org-scoped
	// rows created in Settings). An unknown profile degrades to the zero
	// definition — phases gated on its flags simply stay off, with a loud
	// warning instead of silently pretending everything is fine.
	profile, profileOK := domain.Profiles[scan.Profile]
	if !profileOK {
		if def, derr := e.Orch.ResolveProfile(ctx, "", scan.Profile); derr == nil {
			profile, profileOK = *def, true
		}
	}
	if !profileOK {
		e.Log.Warn("scan references an unknown profile - running with phase gating off", "profile", string(scan.Profile))
	}
	// Custom presets ship validated extra nmap arguments in their spec; the
	// orchestrator already copied them into the scan config at create time.
	if scan.Config != nil && profileOK && len(profile.ExtraArgs) > 0 && len(scan.Config.ExtraArgs) == 0 {
		scan.Config.ExtraArgs = profile.ExtraArgs
	}

	// Agent-less SSH inventory: the scan
	// never touches the nmap pipeline — targets come from the scanner's
	// SSH configuration, not from the site scope.
	if profileOK && profile.SSHCollect {
		return e.RunSSHInventory(ctx, scan, scannerID)
	}

	// Backfill port-selection semantics for scans created before the config
	// carried them (older queued scans, manual DB inserts).
	if scan.Config.TopTCPPorts == 0 && !scan.Config.FullTCPPorts && len(scan.Config.TCPPorts) == 0 {
		if profile.FullPortScan {
			scan.Config.FullTCPPorts = true
		} else if profile.TopTCPPorts > 0 {
			scan.Config.TopTCPPorts = profile.TopTCPPorts
		}
	}
	scope, err := e.Orch.Scope(ctx, scan.ID)
	if err != nil {
		return err
	}
	targets := scope.CIDRs
	if scope == nil || len(targets) == 0 {
		targets = []string{}
	}

	started := time.Now()
	jl := &jobLogger{sink: e.Sink, scanID: scan.ID, orgID: scan.OrganizationID, scannerID: scannerID}
	// Tee raw engine diagnostics (argv, stderr lines) into the job log
	// while the engine still captures full output for parsing.
	if eh, ok := e.Engine.(EngineHooker); ok {
		eh.SetOutputHooks(
			func(argv []string) {
				jl.debug(ctx, domain.SourceEngine, "engine invocation: "+strings.Join(argv, " "), nil)
			},
			func(line string) {
				jl.info(ctx, domain.SourceEngine, line, nil)
			},
		)
		defer eh.SetOutputHooks(nil, nil)
	}
	jl.info(ctx, domain.SourceExec, "scan started", map[string]any{
		"engine": e.Engine.Name(), "profile": string(scan.Profile),
		"targets": len(targets), "scan_name": scan.Name,
	})
	jl.state(ctx, domain.ScanRunning, "discovery", 5, nil)
	_ = e.Orch.UpdateScanState(ctx, scan.ID, domain.ScanRunning, "discovery", 5)
	discoverTask := ids.New()
	e.registerTask(scan.ID, discoverTask)
	defer e.forgetScan(scan.ID)
	_ = e.Orch.CreateTask(ctx, &domain.ScanTask{ID: discoverTask, ScanID: scan.ID, Type: domain.TaskDiscoverHosts, State: domain.TaskRunning, ScannerID: scannerID, Attempt: 1})
	jl.setTask(discoverTask)

	// Immediate cancellation: poll the kill switch while probes are
	// IN FLIGHT and cancel runCtx, which exec.CommandContext turns into
	// a kill of the running nmap process - a cancelled scan must not
	// wait minutes for the current phase to finish (its result is not
	// needed). DB writes below keep the outer ctx so final state
	// updates still persist after cancellation.
	runCtx, killRun := context.WithCancel(ctx)
	defer killRun()
	pollStop := make(chan struct{})
	defer close(pollStop)
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-pollStop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if checkKill(ctx, e.Orch, scan.ID) {
					e.Log.Info("kill switch observed - aborting in-flight probes", "scan", scan.ID)
					jl.warn(ctx, domain.SourceExec, "kill switch observed - aborting in-flight probes", nil)
					killRun()
					return
				}
			}
		}
	}()

	// Phase 1: host discovery.
	hosts, err := e.Engine.DiscoverHosts(runCtx, targets, scan.Config, e.Limits)
	if err != nil {
		if runCtx.Err() != nil {
			return ErrScanCancelled
		}
		return fmt.Errorf("host discovery: %w", err)
	}
	reachable := len(hosts)
	stats := domain.ScanStats{Targets: len(targets), Reachable: reachable, Unreachable: len(targets) - reachable}
	_ = e.Orch.UpdateScanStats(ctx, scan.ID, stats)
	for i, h := range hosts {
		if runCtx.Err() != nil || checkKill(ctx, e.Orch, scan.ID) {
			jl.warn(ctx, domain.SourceExec, "kill switch engaged - aborting between probes", nil)
			return ErrScanCancelled
		}
		payload, _ := json.Marshal(map[string]any{"ip": h.IP, "hostname": h.Hostname, "mac": h.MAC, "mac_vendor": h.MACVendor, "device_type": h.Device})
		_ = e.Orch.RecordObservation(ctx, &domain.Observation{
			ScanID: scan.ID, SiteID: scan.SiteID, OrganizationID: scan.OrganizationID,
			Target: h.IP, ObservationType: "host_up", Timestamp: time.Now().UTC(),
			Source: sourceFor(e.Engine), Payload: payload,
			Normalized: map[string]any{"ip": h.IP, "hostname": h.Hostname, "mac": h.MAC, "mac_vendor": h.MACVendor, "device_type": h.Device},
			Confidence: domain.Confidence(h.Confidence),
		})
		jl.info(ctx, domain.SourceExec, "host up", map[string]any{
			"ip": h.IP, "hostname": h.Hostname, "device": h.Device,
			"progress": 5 + float64(i)/maxF(1, float64(len(hosts)))*20,
		})
		jl.state(ctx, domain.ScanRunning, "discovery", 5+float64(i)/maxF(1, float64(len(hosts)))*20, &stats)
		_ = e.Orch.UpdateScanState(ctx, scan.ID, domain.ScanRunning, "discovery", 5+float64(i)/maxF(1, float64(len(hosts)))*20)

		// Phase 2: ports per host. Profiles with TopTCPPorts 0 and no
		// full range (the fast "trace" profile) skip port scanning
		// entirely: ping sweep + traceroute only, which is what makes
		// the trace fast. Port selection otherwise follows nmap's own
		// top-ports table or the full 65535 range (see portSpecArgs).
		wantPorts := profile.TopTCPPorts > 0 || profile.FullPortScan
		var ports []int
		var portResults []scanner.PortResult
		if wantPorts {
			portResults, err = e.Engine.ScanPorts(runCtx, h.IP, ports, scan.Config, e.Limits)
			if err != nil {
				e.Log.Warn("port scan failed", "host", h.IP, "err", err)
				portResults = nil // one host failing never fails the scan
			}
			for _, pr := range portResults {
				payload, _ := json.Marshal(map[string]any{"ip": h.IP, "port": pr.Port, "protocol": pr.Protocol, "service": pr.Service})
				_ = e.Orch.RecordObservation(ctx, &domain.Observation{
					ScanID: scan.ID, SiteID: scan.SiteID, OrganizationID: scan.OrganizationID,
					Target: h.IP, ObservationType: "port_open", Timestamp: time.Now().UTC(),
					Source: sourceFor(e.Engine), Payload: payload,
					Normalized: map[string]any{"ip": h.IP, "port": float64(pr.Port), "protocol": pr.Protocol, "service": pr.Service},
					Confidence: 0.9,
				})
			}
		}
		stats.PortsDiscovered += len(portResults)
		if wantPorts {
			openList := make([]int, 0, len(portResults))
			for _, pr := range portResults {
				openList = append(openList, pr.Port)
			}
			jl.info(ctx, domain.SourceExec, "port scan finished", map[string]any{
				"ip": h.IP, "open": len(portResults), "ports": firstInts(openList, 25),
			})
			jl.state(ctx, domain.ScanRunning, "ports", 35, &stats)
		} else {
			jl.debug(ctx, domain.SourceExec, "port scan skipped by profile", map[string]any{"ip": h.IP})
		}
		_ = e.Orch.UpdateScanStats(ctx, scan.ID, stats)
		_ = e.Orch.UpdateScanState(ctx, scan.ID, domain.ScanRunning, "ports", 35)

		// Phase 3: service fingerprinting when the profile allows.
		// ServiceLite profiles (fingerprint) get ONE batched
		// -sV --version-light pass instead: cheap, but enough to fill
		// the service table's ostype/CPE fields — the OS+device signal
		// that keeps working where -O cannot fingerprint (no raw
		// sockets, NAT filtering the open+closed port pair).
		// Observations flow through the same "service" path, so
		// RecordOS/RecordDevice/software apply identically.
		if profile.ServiceDetect {
			for _, pr := range portResults {
				svc, err := e.Engine.FingerprintService(runCtx, h.IP, pr.Port, pr.Protocol, scan.Config, e.Limits)
				if err != nil || svc == nil {
					continue
				}
				if err := e.recordServiceObservation(ctx, scan, h.IP, svc); err == nil {
					stats.ServicesFingerprinted++
					jl.info(ctx, domain.SourceExec, "service identified", map[string]any{
						"ip": h.IP, "port": svc.Port, "service": svc.Name,
						"product": svc.Product, "version": svc.Version, "cpe": svc.CPE,
					})
				} else {
					jl.warn(ctx, domain.SourceExec, "service observation failed", map[string]any{"ip": h.IP, "port": svc.Port, "error": err.Error()})
				}
			}
		} else if profile.ServiceLite && len(portResults) > 0 {
			openPorts := make([]int, 0, len(portResults))
			for _, pr := range portResults {
				if pr.Port > 0 {
					openPorts = append(openPorts, pr.Port)
				}
			}
			svcs, liteErr := e.Engine.FingerprintServicesLite(runCtx, h.IP, openPorts, scan.Config, e.Limits)
			if liteErr != nil {
				e.Log.Warn("light service pass failed", "host", h.IP, "err", liteErr)
				jl.warn(ctx, domain.SourceEngine, "light service pass failed", map[string]any{"ip": h.IP, "error": liteErr.Error()})
			}
			if len(svcs) > 0 {
				jl.info(ctx, domain.SourceExec, "service pass finished", map[string]any{"ip": h.IP, "services": len(svcs)})
			}
			for i := range svcs {
				if err := e.recordServiceObservation(ctx, scan, h.IP, &svcs[i]); err == nil {
					stats.ServicesFingerprinted++
				}
			}
		}
		// Phase 4: OS + device-type fingerprinting when the profile
		// allows. The observation reuses the host_up shape so the
		// orchestrator's existing os/device handlers update the asset —
		// the latest scan overrides the stored classification. A failing
		// -O run is logged, not swallowed: silent OS gaps cost hours to
		// diagnose in the field.
		if profile.OSDetect {
			osRes, osErr := e.Engine.FingerprintOS(runCtx, h.IP, scan.Config, e.Limits)
			switch {
			case osErr != nil:
				e.Log.Warn("os fingerprint failed", "host", h.IP, "err", osErr)
				jl.warn(ctx, domain.SourceEngine, "os fingerprint failed", map[string]any{"ip": h.IP, "error": osErr.Error()})
			case osRes == nil || (osRes.Name == "" && osRes.Family == "" && osRes.Device == ""):
				e.Log.Info("os fingerprint inconclusive", "host", h.IP)
			default:
				// A MAC first seen during -O still reaches the inventory:
				// merge into the host result and ride it on this
				// host_up observation.
				if osRes.MAC != "" && h.MAC == "" {
					h.MAC = osRes.MAC
				}
				if osRes.MACVendor != "" && h.MACVendor == "" {
					h.MACVendor = osRes.MACVendor
				}
				payload, _ := json.Marshal(map[string]any{"ip": h.IP, "os_family": osRes.Family, "os_name": osRes.Name, "os_version": osRes.Version, "device_type": osRes.Device, "mac": h.MAC, "mac_vendor": h.MACVendor})
				_ = e.Orch.RecordObservation(ctx, &domain.Observation{
					ScanID: scan.ID, SiteID: scan.SiteID, OrganizationID: scan.OrganizationID,
					Target: h.IP, ObservationType: "host_up", Timestamp: time.Now().UTC(),
					Source: sourceFor(e.Engine), Payload: payload,
					Normalized: map[string]any{"ip": h.IP, "os_family": osRes.Family, "os_name": osRes.Name, "os_version": osRes.Version, "device_type": osRes.Device, "mac": h.MAC, "mac_vendor": h.MACVendor},
					Confidence: domain.Confidence(osRes.Confidence),
				})
				jl.info(ctx, domain.SourceExec, "os fingerprint", map[string]any{
					"ip": h.IP, "os": osRes.Name, "family": osRes.Family, "device": osRes.Device, "confidence": osRes.Confidence,
				})
			}
		}
		// Phase 5: topology tracing. A traceroute per host
		// builds the site's network graph: gateway -> routers -> host.
		// When tracing is impossible (filtered probes, no privileges)
		// we still emit the gateway link so the topology view shows the
		// subnet structure instead of an empty graph — but tagged as a
		// gateway GUESS at low confidence: blocked probes must never be
		// reported as an observed route, nor silently as "no route".
		if profile.Traceroute {
			_ = e.Orch.UpdateScanState(ctx, scan.ID, domain.ScanRunning, "topology", 80)
			jl.state(ctx, domain.ScanRunning, "topology", 80, &stats)
			tr, terr := e.Engine.Traceroute(runCtx, h.IP, scan.Config, e.Limits)
			hops, probe := tr.Hops, tr.Method
			method, conf := "traceroute", 0.85
			if terr != nil {
				e.Log.Warn("traceroute failed; falling back to subnet gateway guess", "host", h.IP, "err", terr)
				jl.warn(ctx, domain.SourceEngine, "traceroute failed; falling back to gateway guess", map[string]any{"ip": h.IP, "error": terr.Error()})
			}
			if terr != nil || len(hops) == 0 {
				if gw := scanner.GatewayOf(h.IP); gw != "" {
					hops = []scanner.Hop{{TTL: 1, IP: gw}, {TTL: 2, IP: h.IP}}
					method, probe = "gateway-guess", ""
					conf = 0.5
				}
			} else if linked := scanner.EnsureGatewayLink(hops, h.IP); len(linked) != len(hops) {
				// Direct L2 adjacency: the trace reached the target in a single
				// hop, which cannot form an edge on its own. The gateway link is
				// synthesized (EnsureGatewayLink) so LAN topology scans of a
				// subnet connect every host instead of drawing isolated dots;
				// the confidence reflects an inferred, not observed, route.
				hops, method, conf = linked, "gateway-l2", 0.65
				probe = "" // the synthesized link has no probe of its own
			}
			if len(hops) > 0 {
				path := make([]map[string]any, 0, len(hops))
				for _, hop := range hops {
					m := map[string]any{"ip": hop.IP, "ttl": hop.TTL}
					if hop.Hostname != "" {
						m["hostname"] = hop.Hostname
					}
					if hop.RTTms > 0 {
						m["rtt_ms"] = hop.RTTms
					}
					path = append(path, m)
				}
				// complete=true when the path structurally ends on
				// the target; TTL gaps mark non-responsive hops
				// (gap count = highest TTL - hops_responded).
				complete := path[len(path)-1]["ip"] == h.IP
				topoPayload, _ := json.Marshal(map[string]any{"ip": h.IP, "method": method, "probe": probe, "hops": len(path)})
				if err := e.Orch.RecordObservation(ctx, &domain.Observation{
					ScanID: scan.ID, SiteID: scan.SiteID, OrganizationID: scan.OrganizationID,
					Target: h.IP, ObservationType: "topology", Timestamp: time.Now().UTC(),
					Source: sourceFor(e.Engine), Payload: topoPayload,
					Normalized: map[string]any{"ip": h.IP, "method": method, "probe": probe, "path": path,
						"complete": complete, "hops_responded": len(path),
						// Raw probe output (nmap XML / tracert text) rides along for
						// the per-asset trace view; bounded so one pathological run
						// cannot bloat the row.
						"raw": truncateRaw(tr.Raw, 24<<10)},
					Confidence: domain.Confidence(conf),
				}); err != nil {
					e.Log.Warn("topology observation failed", "host", h.IP, "err", err)
				}
				jl.info(ctx, domain.SourceExec, "topology traced", map[string]any{
					"ip": h.IP, "method": method, "hops": len(path), "complete": complete,
				})
			}
		}
	}
	_ = e.Orch.UpdateTaskState(ctx, discoverTask, domain.TaskSucceeded, "")
	_ = e.Orch.UpdateScanStats(ctx, scan.ID, stats)
	_ = e.Orch.UpdateScanState(ctx, scan.ID, domain.ScanCompleted, "completed", 100)
	e.Log.Info("scan completed", "scan", scan.ID, "hosts", reachable, "ports", stats.PortsDiscovered, "runtime_os", runtime.GOOS)
	jl.state(ctx, domain.ScanCompleted, "completed", 100, &stats)
	jl.info(ctx, domain.SourceExec, "scan completed", map[string]any{
		"hosts": reachable, "ports": stats.PortsDiscovered, "services": stats.ServicesFingerprinted,
		"duration_ms": time.Since(started).Milliseconds(),
	})
	// Notify the control plane: the server correlates the new services
	// against the vulnerability index (KEV/EPSS/CVE) and raises findings.
	if err := e.Orch.PublishScanResult(ctx, scan.ID, domain.ScanCompleted); err != nil {
		e.Log.Warn("scan result publish failed", "err", err)
	}
	return nil
}

// recordServiceObservation emits the normalized "service" observation shared
// by the per-port ServiceDetect pass and the batched ServiceLite pass. The
// orchestrator turns it into service records, OS hints (service table ostype
// + OS CPEs), device-type hints and software rows.
func (e *Executor) recordServiceObservation(ctx context.Context, scan *domain.Scan, ip string, svc *scanner.ServiceResult) error {
	payload, _ := json.Marshal(map[string]any{
		"ip": ip, "port": svc.Port, "protocol": svc.Protocol, "service": svc.Name,
		"product": svc.Product, "vendor": svc.Vendor, "version": svc.Version, "cpe": svc.CPE, "cpes": svc.CPEs, "banner": svc.Banner,
	})
	norm := map[string]any{
		"ip": ip, "port": float64(svc.Port), "protocol": svc.Protocol, "service": svc.Name,
		"product": svc.Product, "vendor": svc.Vendor, "version": svc.Version,
	}
	if svc.CPE != "" {
		norm["cpe"] = svc.CPE
	}
	if len(svc.CPEs) > 0 {
		norm["cpes"] = svc.CPEs
	}
	if svc.Banner != "" {
		norm["banner"] = svc.Banner
	}
	if svc.OSType != "" {
		norm["os"] = svc.OSType // weak OS hint from the service table
	}
	return e.Orch.RecordObservation(ctx, &domain.Observation{
		ScanID: scan.ID, SiteID: scan.SiteID, OrganizationID: scan.OrganizationID,
		Target: ip, ObservationType: "service", Timestamp: time.Now().UTC(),
		Source: sourceFor(e.Engine), Payload: payload, Normalized: norm,
		Confidence: domain.Confidence(svc.Confidence),
	})
}

// checkKill polls the kill switch between probes.
func checkKill(ctx context.Context, orch Orch, scanID string) bool {
	scan, err := orch.ScanByID(ctx, "", scanID)
	if err != nil {
		return false
	}
	return scan.KillSwitch || scan.State == domain.ScanCancelling
}

func sourceFor(e scanner.Engine) domain.Source {
	if e.Name() == "simulated" {
		return domain.SourceSimulated
	}
	return domain.Source(e.Name())
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// firstInts renders the first N entries of a port list for log lines.
func firstInts(list []int, n int) []int {
	if len(list) <= n {
		return list
	}
	return list[:n]
}

// truncateRaw bounds stored probe output; the tail is marked so operators
// can tell a cut from a complete dump.
func truncateRaw(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n... [truncated]"
}
