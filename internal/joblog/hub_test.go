package joblog

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestHubRoutingByChannelAndOrg(t *testing.T) {
	h := NewHub()
	a := h.Subscribe("org-a")
	b := h.Subscribe("org-b")
	a.Join("scan:s1", "notify")
	b.Join("scan:s1", "notify")

	payload, _ := json.Marshal(map[string]string{"msg": "hello"})
	// Org mismatch: org-b must NOT receive org-a's scan event.
	h.Publish(&Event{OrgID: "org-a", Channel: "scan:s1", Kind: KindLog, Data: payload})
	select {
	case ev := <-a.C():
		if ev.Channel != "scan:s1" || ev.Kind != KindLog {
			t.Fatalf("wrong event routed: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("org-a subscriber did not receive its event")
	}
	select {
	case ev := <-b.C():
		t.Fatalf("org-b subscriber received foreign-org event: %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}

	// Notify: org scoped.
	h.Publish(&Event{OrgID: "org-b", Channel: "notify", Kind: KindNotification, Data: payload})
	select {
	case ev := <-b.C():
		if ev.Kind != KindNotification {
			t.Fatalf("expected notification kind, got %s", ev.Kind)
		}
	case <-time.After(time.Second):
		t.Fatal("org-b did not receive its notification")
	}
	select {
	case <-a.C():
		t.Fatal("org-a received org-b notification")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestHubSlowConsumerEvicted(t *testing.T) {
	h := NewHub()
	s := h.Subscribe("org")
	s.Join("scan:s1")
	// Fill the buffer without reading; the next publish after overflow
	// must evict the sub, not block the publisher.
	for i := 0; i < subBuf+1; i++ {
		h.Publish(&Event{OrgID: "org", Channel: "scan:s1", Kind: KindLog, Data: []byte("{}")})
	}
	deadline := time.After(2 * time.Second)
	for h.Subscribers() != 0 {
		select {
		case <-deadline:
			t.Fatal("slow subscriber was not evicted")
		case <-time.After(5 * time.Millisecond):
		}
	}
	// Draining a closed channel yields zero values forever; the reader
	// side (websocket writer) selects on the done channel too.
	if _, ok := <-s.C(); ok {
		t.Log("channel still open with buffered events — acceptable, sub is removed")
	}
}

func TestHubJoinLeave(t *testing.T) {
	h := NewHub()
	s := h.Subscribe("org")
	s.Join("scan:s1")
	s.Leave("scan:s1")
	h.Publish(&Event{OrgID: "org", Channel: "scan:s1", Kind: KindLog, Data: []byte("{}")})
	select {
	case ev := <-s.C():
		t.Fatalf("event delivered after Leave: %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestHubUnsubscribeClosesOnce(t *testing.T) {
	h := NewHub()
	s := h.Subscribe("org")
	s.Join("notify")
	s.Unsubscribe()
	s.Unsubscribe() // idempotent
	// Concurrent publish while closing must not panic.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.Publish(&Event{OrgID: "org", Channel: "notify", Kind: KindNotification, Data: []byte("{}")})
		}()
	}
	wg.Wait()
}
