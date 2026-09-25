package alerting

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// Delivery limits (plan §5.9): bounded timeout, bounded response size,
// HTTPS by default, no redirects (each hop would need its own SSRF check),
// exponential backoff and a dead state for manual replay.
const (
	deliveryTimeout     = 10 * time.Second
	maxResponseBytes    = 64 << 10
	maxDeliveryAttempts = 5
)

// DeliveryWorker claims due deliveries and performs webhook sends. The
// in-app alert IS the occurrence (persisted before any delivery); in-app
// destinations are recorded for history/health and complete immediately.
type DeliveryWorker struct {
	DB     *pg.DB
	Log    *slog.Logger
	Client *http.Client
	// AllowInsecure permits plain-HTTP webhooks (development only) and is
	// also what allows loopback targets in tests.
	AllowInsecure bool
	Interval      time.Duration
	Now           func() time.Time
}

// Run blocks until ctx is done.
func (w *DeliveryWorker) Run(ctx context.Context) {
	if w.Interval <= 0 {
		w.Interval = 5 * time.Second
	}
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.RunOnce(ctx)
		}
	}
}

// RunOnce claims and processes one batch. Returns the number processed.
func (w *DeliveryWorker) RunOnce(ctx context.Context) int {
	// Claim atomically: status moves to retry and attempts increment in the
	// claiming statement, so two workers can never take the same row.
	sql := `UPDATE alert_deliveries SET status = 'retry', attempts = attempts + 1
		WHERE id IN (
			SELECT id FROM alert_deliveries
			WHERE status IN ('pending','retry') AND next_attempt_at <= $1
			ORDER BY next_attempt_at
			LIMIT 10
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, organization_id, occurrence_id, destination_id, kind, status, attempts, next_attempt_at,
			last_status_code, last_error, idempotency_key, payload, created_at`
	rows, err := w.DB.Pool.Query(ctx, sql, w.now())
	if err != nil {
		w.Log.Warn("delivery claim failed", "err", err)
		return 0
	}
	var claimed []*domain.Delivery
	for rows.Next() {
		var d domain.Delivery
		if err := rows.Scan(&d.ID, &d.OrgID, &d.OccurrenceID, &d.DestinationID, &d.Kind, &d.Status,
			&d.Attempts, &d.NextAttemptAt, &d.LastStatusCode, &d.LastError, &d.IdempotencyKey,
			&d.Payload, &d.CreatedAt); err != nil {
			rows.Close()
			w.Log.Warn("delivery scan failed", "err", err)
			return 0
		}
		claimed = append(claimed, &d)
	}
	rows.Close()
	for _, d := range claimed {
		w.process(ctx, d)
	}
	return len(claimed)
}

func (w *DeliveryWorker) process(ctx context.Context, d *domain.Delivery) {
	dest, err := pg.NewDestinationRepo(w.DB).GetRaw(ctx, d.DestinationID)
	if err != nil {
		w.finish(ctx, d, false, 0, "destination missing: "+err.Error())
		return
	}
	if !dest.Enabled {
		w.finish(ctx, d, false, 0, "destination disabled")
		return
	}
	if dest.Kind == domain.DestinationInApp {
		// The occurrence row is the in-app notification; nothing to send.
		w.finish(ctx, d, true, 0, "")
		return
	}
	status, err := w.sendWebhook(ctx, dest, d)
	w.finish(ctx, d, err == nil, status, errString(err))
}

// sendWebhook performs one signed delivery.
func (w *DeliveryWorker) sendWebhook(ctx context.Context, dest *domain.Destination, d *domain.Delivery) (int, error) {
	u, err := SafeWebhookURL(dest.URL, w.AllowInsecure)
	if err != nil {
		return 0, err
	}
	body := []byte(d.Payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Aegis-Alerts/1.0")
	req.Header.Set("X-Aegis-Event", d.Kind)
	req.Header.Set("X-Aegis-Delivery", d.IdempotencyKey)
	req.Header.Set("X-Aegis-Org", d.OrgID)
	if dest.Secret != "" {
		mac := hmac.New(sha256.New, []byte(dest.Secret))
		mac.Write(body)
		req.Header.Set("X-Aegis-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	client := w.Client
	if client == nil {
		client = &http.Client{
			Timeout: deliveryTimeout,
			// Never follow redirects: a 3xx would re-POST to a target that
			// has not passed the SSRF check.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// finish records the outcome: sent, scheduled retry or dead letter.
func (w *DeliveryWorker) finish(ctx context.Context, d *domain.Delivery, ok bool, status int, errMsg string) {
	now := w.now()
	if ok {
		_, err := w.DB.Pool.Exec(ctx, `UPDATE alert_deliveries SET status = 'sent', sent_at = $2, last_error = '', last_status_code = $3 WHERE id = $1`,
			d.ID, now, nullInt(status))
		if err != nil {
			w.Log.Warn("delivery finish failed", "err", err)
		}
		_ = pg.NewDestinationRepo(w.DB).MarkResult(ctx, d.DestinationID, true, "")
		return
	}
	if d.Attempts >= maxDeliveryAttempts || d.Kind == domain.DeliveryTest {
		_, err := w.DB.Pool.Exec(ctx, `UPDATE alert_deliveries SET status = 'dead', last_error = $2, last_status_code = $3 WHERE id = $1`,
			d.ID, errMsg, nullInt(status))
		if err != nil {
			w.Log.Warn("delivery dead-letter failed", "err", err)
		}
		_ = pg.NewDestinationRepo(w.DB).MarkResult(ctx, d.DestinationID, false, errMsg)
		return
	}
	next := now.Add(time.Duration(1<<uint(d.Attempts)) * 30 * time.Second) // 30s, 1m, 2m, 4m...
	_, err := w.DB.Pool.Exec(ctx, `UPDATE alert_deliveries SET status = 'retry', next_attempt_at = $2, last_error = $3, last_status_code = $4 WHERE id = $1`,
		d.ID, next, errMsg, nullInt(status))
	if err != nil {
		w.Log.Warn("delivery retry schedule failed", "err", err)
	}
	_ = pg.NewDestinationRepo(w.DB).MarkResult(ctx, d.DestinationID, false, errMsg)
}

// ReplayDead requeues every dead delivery for one destination.
func ReplayDead(ctx context.Context, db *pg.DB, orgID, destinationID string) (int64, error) {
	tag, err := db.Pool.Exec(ctx, `UPDATE alert_deliveries SET status = 'pending', attempts = 0, next_attempt_at = now()
		WHERE organization_id = $1 AND destination_id = $2 AND status = 'dead'`, orgID, destinationID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// --- SSRF guard ---------------------------------------------------------------

// SafeWebhookURL validates a webhook URL: HTTPS by default (plain HTTP and
// private/loopback targets only with the explicit development flag, which
// is exactly what development and tests need) and no private/loopback/
// link-local targets otherwise. Every resolved address is checked, not
// just the first.
func SafeWebhookURL(raw string, allowInsecure bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("webhook url: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecure {
			return nil, errors.New("webhook url must use https")
		}
	default:
		return nil, fmt.Errorf("webhook url scheme %q is not allowed", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("webhook url has no host")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("webhook host resolve: %w", err)
	}
	for _, ip := range ips {
		// Link-local addresses (cloud metadata endpoints) and multicast are
		// forbidden unconditionally — no development scenario needs them.
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
			return nil, fmt.Errorf("webhook host resolves to a forbidden address (%s)", ip)
		}
		// Loopback/private are forbidden unless the development flag allows
		// them (httptest servers, local receivers).
		if !allowInsecure && isForbiddenIP(ip) {
			return nil, fmt.Errorf("webhook host resolves to a forbidden address (%s)", ip)
		}
	}
	return u, nil
}

func isForbiddenIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// --- small helpers -------------------------------------------------------------

func (w *DeliveryWorker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now().UTC()
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func nullInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}
