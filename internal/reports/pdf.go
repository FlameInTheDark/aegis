// Minimal PDF 1.4 writer for report artifacts. Produces real,
// multi-page PDFs with the standard Helvetica/Courier base fonts — no
// external binary, no CGO — so the worker image stays small and output
// opens in every PDF viewer. Tabular data uses fixed-pitch Courier columns
// so alignment is exact without font metric tables.
package reports

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

const (
	pdfPageW  = 595.0 // A4 portrait, points
	pdfPageH  = 842.0
	pdfMargin = 48.0
	pdfBottom = 56.0 // space reserved for the footer
)

// pdfCanvas accumulates text/line operations per page and wraps to a new
// page when the cursor would cross the bottom margin.
type pdfCanvas struct {
	pages [][]string // finished pages (content operations)
	ops   []string   // current page operations
	y     float64    // cursor, measured from the top of the page
}

func newPDFCanvas() *pdfCanvas {
	// y is the distance from the TOP of the page; the first line sits one
	// margin below the top edge and grows downward as content is added.
	c := &pdfCanvas{y: pdfMargin}
	c.ops = make([]string, 0, 256)
	return c
}

func (c *pdfCanvas) newPage() {
	c.pages = append(c.pages, c.ops)
	c.ops = make([]string, 0, 256)
	c.y = pdfMargin
}

// ensure starts a new page when the cursor would cross the bottom margin.
func (c *pdfCanvas) ensure(space float64) {
	if c.y+space > pdfPageH-pdfBottom-16 {
		c.newPage()
	}
}

func (c *pdfCanvas) text(x, size float64, font, s string) {
	// PDF text space is measured from the bottom; convert the top-down
	// cursor into a baseline coordinate.
	c.ops = append(c.ops, fmt.Sprintf("BT /%s %s Tf 1 0 0 1 %s %s Tm (%s) Tj ET",
		font, pdfNum(size), pdfNum(x), pdfNum(pdfPageH-c.y-size), pdfEscape(s)))
}

// grayLevel renders text in a gray level (0=black .. 1=white), then resets.
// Grayscale uses the single-operand `g` operator (`rg` requires three).
func (c *pdfCanvas) gray(x, size float64, level float64, font, s string) {
	c.ops = append(c.ops, fmt.Sprintf("%s g", pdfNum(level)))
	c.text(x, size, font, s)
	c.ops = append(c.ops, "0 g")
}

func (c *pdfCanvas) rule() {
	y := pdfPageH - c.y
	c.ops = append(c.ops, fmt.Sprintf("0.85 w 0.8 G %s %s m %s %s l S 0 G",
		pdfNum(pdfMargin), pdfNum(y), pdfNum(pdfPageW-pdfMargin), pdfNum(y)))
}

// finish closes the current page and returns all page content streams.
func (c *pdfCanvas) finish() [][]string {
	c.pages = append(c.pages, c.ops)
	return c.pages
}

func pdfNum(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}

// pdfEscape escapes a PDF literal string. WinAnsi-encodable characters
// (Latin-1 range) are emitted directly; other non-ASCII characters map to
// their closest ASCII stand-in (dashes, quotes, arrows) or '?' so text
// never silently degrades to raw '?' for typographic separators.
func pdfEscape(s string) string {
	replace := strings.NewReplacer(
		"·", "-", "—", "-", "–", "-", "−", "-",
		"’", "'", "‘", "'", "“", "\"", "”", "\"",
		"→", "->", "≥", ">=", "≤", "<=",
	)
	s = replace.Replace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\\' || r == '(' || r == ')':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 32:
			b.WriteByte(' ')
		case r > 126 && r < 256:
			b.WriteRune(r) // WinAnsi = Latin-1 for these code points
		case r > 126:
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// pdfWrap breaks s into lines fitting a fixed-pitch (Courier) column.
func pdfWrap(s string, size, width float64) []string {
	maxChars := int(width / (0.6 * size))
	if maxChars < 8 {
		maxChars = 8
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	cur := ""
	for _, w := range words {
		switch {
		case cur == "":
			cur = w
		case len(cur)+1+len(w) <= maxChars:
			cur += " " + w
		default:
			lines = append(lines, cur)
			cur = w
		}
		for len(cur) > maxChars { // very long single token
			lines = append(lines, cur[:maxChars])
			cur = cur[maxChars:]
		}
	}
	lines = append(lines, cur)
	return lines
}

// renderPDF renders the report as a real PDF document.
func renderPDF(d *reportData) ([]byte, string, error) {
	c := newPDFCanvas()
	const (
		textSize  = 9.0
		lead      = 13.0
		h1Size    = 18.0
		h2Size    = 12.5
		innerW    = pdfPageW - 2*pdfMargin
		labelCol  = 170.0
		valueColX = pdfMargin + labelCol
	)

	// Title + meta. The 18pt title advances its full glyph height plus a
	// 10pt gap before the 8.5pt meta line, so the two never overlap; the
	// meta itself wraps instead of colliding with the rule below it.
	c.ensure(h1Size + lead)
	c.text(pdfMargin, h1Size, "F2", d.Title)
	c.y += h1Size + 10
	meta := fmt.Sprintf("Generated %s UTC - Organization %s%s", d.GeneratedAt.Format("2006-01-02 15:04:05"), d.OrgLabel, siteSuffix(d.SiteLabel))
	for _, line := range pdfWrap(meta, 8.5, innerW) {
		c.ensure(12)
		c.gray(pdfMargin, 8.5, 0.45, "F1", line)
		c.y += 12
	}
	c.y += 4
	c.rule()
	c.y += lead

	// Summary block as label/value rows (fixed columns, Courier values).
	row := func(label, value string) {
		c.ensure(lead)
		c.gray(pdfMargin, textSize, 0.35, "F1", label)
		c.text(valueColX, textSize, "F3", value)
		c.y += lead
	}
	row("Total findings:", fmt.Sprint(d.Summary["total_findings"]))
	row("Known exploited (KEV):", fmt.Sprint(d.Summary["kev"]))
	if bySev, ok := d.Summary["by_severity"].(map[string]int); ok {
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if n := bySev[sev]; n > 0 {
				row("Severity "+sev+":", fmt.Sprint(n))
			}
		}
	}
	if n, ok := d.Summary["assets"].(int); ok {
		row("Assets in scope:", fmt.Sprint(n))
	}
	if n, ok := d.Summary["open_ports"]; ok {
		row("Open ports:", fmt.Sprint(n))
	}
	c.y += 6
	c.rule()
	c.y += lead

	// Recommendations.
	if len(d.Recommendations) > 0 {
		c.ensure(h2Size + lead)
		c.text(pdfMargin, h2Size, "F2", "Recommendations")
		c.y += lead + 2
		for _, r := range d.Recommendations {
			for i, line := range pdfWrap("- "+r, textSize, innerW) {
				c.ensure(lead)
				c.text(pdfMargin+float64(i)*8, textSize, "F1", line)
				c.y += lead
			}
		}
		c.y += 6
		c.rule()
		c.y += lead
	}

	// Findings as fixed-pitch rows with a wrapped title column.
	if len(d.Findings) > 0 {
		// Human labels for asset references: hostname → primary IP.
		// Detail reports gather every finding's device, inventory-style
		// reports the full asset list, so the ASSET column never prints
		// a machine UUID to a human reader.
		assetNames := make(map[string]string, len(d.Assets))
		for _, a := range d.Assets {
			assetNames[a.ID] = assetLabel(a)
		}
		if d.Details != nil {
			for _, dev := range d.Details.Devices {
				assetNames[dev.Asset.ID] = assetLabel(dev.Asset)
			}
		}
		c.ensure(h2Size + lead)
		c.text(pdfMargin, h2Size, "F2", fmt.Sprintf("Findings (%d)", len(d.Findings)))
		c.y += lead + 2
		const (
			riskW  = 34
			sevW   = 46
			cveW   = 88
			statW  = 62
			assetW = 68
		)
		titleW := innerW - float64(riskW+sevW+cveW+statW+assetW+5*8) - 8
		c.gray(pdfMargin, 8, 0.35, "F3", fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s %s",
			riskW, "RISK", sevW, "SEVERITY", cveW, "CVE", statW, "STATUS", assetW, "ASSET", "TITLE"))
		c.y += lead
		for _, f := range d.Findings {
			asset := f.AssetID
			if label, ok := assetNames[f.AssetID]; ok && label != "" {
				asset = label
			}
			if len(asset) > assetW {
				asset = asset[:assetW]
			}
			title := f.Title
			if title == "" {
				title = f.CVEID
			}
			first := fmt.Sprintf("%*.0f %-*s %-*s %-*s %-*s ",
				riskW, f.RiskScore, sevW, string(f.Severity), cveW, f.CVEID, statW, string(f.Status), assetW, asset)
			indent := strings.Repeat(" ", len(first))
			lines := pdfWrap(title, 8.0, titleW)
			for i, line := range lines {
				c.ensure(lead)
				if i == 0 {
					c.text(pdfMargin, 8.0, "F3", first+line)
				} else {
					c.gray(pdfMargin, 8.0, 0.4, "F3", indent+line)
				}
				c.y += lead
			}
		}
		c.y += 6
		c.rule()
		c.y += lead
	}

	// Assets.
	if len(d.Assets) > 0 {
		c.ensure(h2Size + lead)
		c.text(pdfMargin, h2Size, "F2", fmt.Sprintf("Assets (%d)", len(d.Assets)))
		c.y += lead + 2

		for _, a := range d.Assets {
			host := assetLabel(a)
			osName := a.OSName
			if osName == "" {
				osName = "unknown"
			}
			c.ensure(lead * 4)
			for _, line := range pdfWrap(host, textSize, innerW) {
				c.ensure(lead)
				c.text(pdfMargin, textSize, "F2", line)
				c.y += lead
			}
			info := fmt.Sprintf("OS: %s | Type: %s | Open ports: %d | Risk: %.0f | Criticality: %s | Exposure: %s", osName, a.DeviceType, d.OpenPortsByAsset[a.ID], a.RiskScore, a.Criticality, a.Exposure)
			for _, line := range pdfWrap(info, textSize, innerW) {
				c.ensure(lead)
				c.text(pdfMargin, textSize, "F3", line)
				c.y += lead
			}
			c.y += 5
		}
	}

	// Detail sections (site_detail / device_detail): the full stored record
	// set per device, plus explicit coverage/omission statements. Machine
	// IDs (asset/service/finding/scan UUIDs) are never rendered; humans get
	// names, addresses, ports and versions.
	if d.Details != nil {
		emitList := func(title string, items []string) {
			if len(items) == 0 {
				return
			}
			c.ensure(h2Size + lead)
			c.text(pdfMargin, h2Size, "F2", title)
			c.y += lead + 2
			for _, item := range items {
				for _, line := range pdfWrap("- "+item, textSize, innerW) {
					c.ensure(lead)
					c.text(pdfMargin, textSize, "F1", line)
					c.y += lead
				}
			}
			c.y += 6
			c.rule()
			c.y += lead
		}
		emitList("Coverage", d.Details.Coverage)
		emitList("Omitted from this report", d.Details.Omitted)

		if d.Details.Site != nil {
			s := d.Details.Site
			c.ensure(h2Size + lead)
			c.text(pdfMargin, h2Size, "F2", "Site")
			c.y += lead + 2
			row("Name:", s.Name)
			row("Type:", s.SiteType)
			if s.Description != "" {
				for _, line := range pdfWrap("Description: "+s.Description, textSize, innerW) {
					c.ensure(lead)
					c.text(pdfMargin, textSize, "F3", line)
					c.y += lead
				}
			}
			c.y += 4
			c.rule()
			c.y += lead
		}
		if len(d.Details.Networks) > 0 {
			c.ensure(h2Size + lead)
			c.text(pdfMargin, h2Size, "F2", fmt.Sprintf("Networks (%d)", len(d.Details.Networks)))
			c.y += lead + 2
			for _, n := range d.Details.Networks {
				line := n.CIDR
				if n.VLANID != nil {
					line += fmt.Sprintf(" (VLAN %d)", *n.VLANID)
				}
				if n.Gateway != "" {
					line += " gateway " + n.Gateway
				}
				if n.Name != "" {
					line += " - " + n.Name
				}
				c.ensure(lead)
				c.text(pdfMargin, textSize, "F3", line)
				c.y += lead
			}
			c.y += 4
			c.rule()
			c.y += lead
		}

		for _, dev := range d.Details.Devices {
			a := dev.Asset
			c.ensure(h2Size + lead)
			c.text(pdfMargin, h2Size, "F2", "Device: "+assetLabel(a))
			c.y += lead + 2
			row("Operating system:", orDash(a.OSName+" "+a.OSVersion))
			row("Device type:", string(a.DeviceType))
			row("Criticality / exposure:", fmt.Sprintf("%s / %s", a.Criticality, a.Exposure))
			row("Risk score:", fmt.Sprintf("%.0f", a.RiskScore))
			if len(dev.Identifiers) > 0 {
				parts := make([]string, 0, len(dev.Identifiers))
				for _, idf := range dev.Identifiers {
					parts = append(parts, idf.Type+"="+idf.Value)
				}
				row("Identifiers:", strings.Join(parts, ", "))
			}
			for _, ifc := range dev.Interfaces {
				line := "Interface"
				if ifc.Name != "" {
					line = "Interface " + ifc.Name
				}
				if ifc.MAC != "" {
					line += " MAC " + ifc.MAC
				}
				addrs := make([]string, 0, len(ifc.Addresses))
				for _, ipo := range ifc.Addresses {
					if ipo.IsPrimary {
						addrs = append(addrs, ipo.IP+" (primary)")
					} else {
						addrs = append(addrs, ipo.IP)
					}
				}
				if len(addrs) > 0 {
					line += ": " + strings.Join(addrs, ", ")
				}
				for _, wl := range pdfWrap(line, textSize, innerW) {
					c.ensure(lead)
					c.text(pdfMargin, textSize, "F3", wl)
					c.y += lead
				}
			}
			if len(dev.Services) > 0 {
				c.ensure(lead)
				c.gray(pdfMargin, textSize, 0.35, "F1", "Services (all stored states):")
				c.y += lead
				for _, svc := range dev.Services {
					line := fmt.Sprintf("%d/%s %s", svc.Port, svc.Protocol, svc.State)
					if svc.ServiceName != "" {
						line += " " + svc.ServiceName
					}
					if svc.Product != "" {
						line += " - " + svc.Product
					}
					if svc.DetectedVersion != "" {
						line += " " + svc.DetectedVersion
					}
					if svc.TLS != nil && svc.TLS.SubjectCN != "" {
						line += " (TLS CN " + svc.TLS.SubjectCN + ")"
					}
					if svc.HTTP != nil && svc.HTTP.Title != "" {
						line += " (HTTP title " + svc.HTTP.Title + ")"
					}
					if svc.Banner != "" {
						line += " banner " + clip(svc.Banner, 40)
					}
					for _, wl := range pdfWrap(line, textSize, innerW) {
						c.ensure(lead)
						c.text(pdfMargin, textSize, "F3", wl)
						c.y += lead
					}
				}
			}
			if len(dev.Software) > 0 {
				c.ensure(lead)
				c.gray(pdfMargin, textSize, 0.35, "F1", "Software:")
				c.y += lead
				for _, sw := range dev.Software {
					line := sw.Name
					if sw.Version != "" {
						line += " " + sw.Version
					}
					c.ensure(lead)
					c.text(pdfMargin, textSize, "F3", line)
					c.y += lead
				}
			}
			if len(dev.Evidence) > 0 {
				c.ensure(lead)
				c.gray(pdfMargin, textSize, 0.35, "F1", fmt.Sprintf("Evidence (%d):", len(dev.Evidence)))
				c.y += lead
				for _, ev := range dev.Evidence {
					for _, wl := range pdfWrap("- ["+ev.Kind+"] "+ev.Statement, textSize, innerW) {
						c.ensure(lead)
						c.text(pdfMargin, textSize, "F3", wl)
						c.y += lead
					}
				}
			}
			c.y += 4
			c.rule()
			c.y += lead
		}

		if len(d.Details.Scans) > 0 {
			c.ensure(h2Size + lead)
			c.text(pdfMargin, h2Size, "F2", fmt.Sprintf("Scans (%d)", len(d.Details.Scans)))
			c.y += lead + 2
			for _, sc := range d.Details.Scans {
				line := sc.Name
				if line == "" {
					line = string(sc.Profile)
				}
				line += " - " + string(sc.State) + " - " + sc.CreatedAt.Format("2006-01-02 15:04")
				for _, wl := range pdfWrap(line, textSize, innerW) {
					c.ensure(lead)
					c.text(pdfMargin, textSize, "F3", wl)
					c.y += lead
				}
			}
			c.y += 4
			c.rule()
			c.y += lead
		}
	}

	// Footer with page numbers (added after pagination is known). ASCII
	// only: base-font encoding has no middle dot and renders '?' otherwise.
	pages := c.finish()
	total := len(pages)
	for i, ops := range pages {
		footer := fmt.Sprintf("Page %d of %d - Aegis Security Platform - data visible to the requesting organization only", i+1, total)
		pages[i] = append(ops,
			fmt.Sprintf("0.4 w 0.75 G %s %s m %s %s l S 0 G", pdfNum(pdfMargin), pdfNum(pdfBottom-10), pdfNum(pdfPageW-pdfMargin), pdfNum(pdfBottom-10)),
			fmt.Sprintf("BT /F1 8 Tf 1 0 0 1 %s %s Tm (%s) Tj ET", pdfNum(pdfMargin), pdfNum(pdfBottom-22), pdfEscape(footer)),
		)
	}

	return assemblePDF(pages), "application/pdf", nil
}

func siteSuffix(siteID string) string {
	if siteID == "" {
		return ""
	}
	return " - Site " + siteID
}

// assetLabel mirrors the UI naming: hostname → primary IP → asset id.
func assetLabel(a domain.Asset) string {
	switch {
	case a.Hostname != "":
		return a.Hostname
	case a.PrimaryIP != "":
		return a.PrimaryIP
	case a.FQDN != "":
		return a.FQDN
	default:
		return "Unnamed device"
	}
}

// orDash joins non-empty parts with a space, or returns "-" when all empty.
func orDash(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			kept = append(kept, strings.TrimSpace(p))
		}
	}
	if len(kept) == 0 {
		return "-"
	}
	return strings.Join(kept, " ")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}

// assemblePDF writes the PDF object graph: catalog, page tree, three base
// fonts, then per page one content stream (even number) + page object
// (odd), followed by xref/trailer. Object numbering is 1-based and stable:
// 1 catalog, 2 pages, 3..5 fonts, 6.. content/page pairs.
func assemblePDF(pages [][]string) []byte {
	objs := make([]string, 1, 5+2*len(pages)) // objs[0] unused; numbering = index
	add := func(data string) int {
		objs = append(objs, data)
		return len(objs) - 1 // object number
	}

	firstContent := 6
	var kids strings.Builder
	for i := range pages {
		if i > 0 {
			kids.WriteString(" ")
		}
		kids.WriteString(fmt.Sprintf("%d 0 R", firstContent+1+2*i))
	}
	add(`<< /Type /Catalog /Pages 2 0 R >>`)                                                      // 1
	add(fmt.Sprintf(`<< /Type /Pages /Kids [%s] /Count %d >>`, kids.String(), len(pages)))        // 2
	add(`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>`)      // 3
	add(`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>`) // 4
	add(`<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>`)        // 5
	for _, ops := range pages {
		stream := strings.Join(ops, "\n")
		contentNum := add(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream))
		add(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %s %s] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R >>",
			pdfNum(pdfPageW), pdfNum(pdfPageH), contentNum))
	}

	var out strings.Builder
	out.WriteString("%PDF-1.4\n%âãÏÓ\n")
	offsets := make([]int, len(objs))
	for num := 1; num < len(objs); num++ {
		offsets[num] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", num, objs[num])
	}
	xrefStart := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objs))
	for num := 1; num < len(objs); num++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[num])
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs), xrefStart)
	return []byte(out.String())
}
