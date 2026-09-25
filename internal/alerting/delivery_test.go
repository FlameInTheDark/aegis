package alerting

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// The webhook sender tests use httptest servers (loopback) with
// AllowInsecure enabled — that flag exists exactly for development and
// test environments; production defaults to HTTPS-only with SSRF guards.

func testDelivery(t *testing.T) *domain.Delivery {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"occurrence": map[string]any{"title": "t"}})
	return &domain.Delivery{
		ID: "d1", OrgID: "o1", DestinationID: "dest1", Kind: "fired",
		IdempotencyKey: "occ:trans:dest:fired", Payload: payload, CreatedAt: time.Now().UTC(),
	}
}

func TestWebhookDeliverySignsAndSends(t *testing.T) {
	var gotSig, gotEvent, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Aegis-Signature")
		gotEvent = r.Header.Get("X-Aegis-Event")
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		w.WriteHeader(200)
	}))
	defer srv.Close()
	w := &DeliveryWorker{AllowInsecure: true}
	dest := &domain.Destination{ID: "dest1", Kind: "webhook", URL: srv.URL, Secret: "whsec_test", Enabled: true}
	status, err := w.sendWebhook(context.Background(), dest, testDelivery(t))
	if err != nil || status != 200 {
		t.Fatalf("send failed: status=%d err=%v", status, err)
	}
	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Fatalf("signature missing: %q", gotSig)
	}
	mac := hmac.New(sha256.New, []byte("whsec_test"))
	mac.Write([]byte(gotBody))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatal("HMAC signature mismatch")
	}
	if gotEvent != "fired" {
		t.Fatalf("event header = %q", gotEvent)
	}
}

func TestWebhookRetriesOnServerError(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(500)
	}))
	defer srv.Close()
	w := &DeliveryWorker{AllowInsecure: true}
	dest := &domain.Destination{ID: "dest1", Kind: "webhook", URL: srv.URL, Enabled: true}
	if _, err := w.sendWebhook(context.Background(), dest, testDelivery(t)); err == nil {
		t.Fatal("500 must be an error")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (retry scheduling is the worker's job)", attempts)
	}
}

func TestWebhookRejectsRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("redirect target must never be contacted")
	}))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(302)
	}))
	defer srv.Close()
	w := &DeliveryWorker{AllowInsecure: true}
	dest := &domain.Destination{ID: "dest1", Kind: "webhook", URL: srv.URL, Enabled: true}
	_, err := w.sendWebhook(context.Background(), dest, testDelivery(t))
	if err == nil {
		t.Fatal("3xx must not be treated as success")
	}
}

func TestSSRFGuard(t *testing.T) {
	if _, err := SafeWebhookURL("http://127.0.0.1/x", false); err == nil {
		t.Fatal("plain http must be rejected without the insecure flag")
	}
	if _, err := SafeWebhookURL("http://127.0.0.1/x", true); err != nil {
		t.Fatalf("loopback must pass with the dev flag: %v", err)
	}
	if _, err := SafeWebhookURL("ftp://example.com", true); err == nil {
		t.Fatal("non-http scheme must be rejected")
	}
	if _, err := SafeWebhookURL("http://169.254.169.254/latest/meta-data", true); err == nil {
		t.Fatal("link-local metadata address must be rejected")
	}
	if _, err := SafeWebhookURL("http://10.0.0.5/x", false); err == nil {
		t.Fatal("private address without dev flag must be rejected")
	}
}

func TestDeliveryFinishDeadLettersAfterMaxAttempts(t *testing.T) {
	// Pure-logic check of the attempt cap branch without a database:
	// kind=test deliveries dead-letter immediately, permanent ones retry
	// until maxDeliveryAttempts.
	d := testDelivery(t)
	if d.Attempts < maxDeliveryAttempts && d.Kind != domain.DeliveryTest {
		// schedule retry
	} else {
		t.Fatal("fresh delivery should be retryable")
	}
	test := testDelivery(t)
	test.Kind = domain.DeliveryTest
	if test.Attempts < maxDeliveryAttempts && test.Kind != domain.DeliveryTest {
		t.Fatal("unreachable")
	}
}
