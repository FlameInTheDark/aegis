package ids

import (
	"testing"
	"time"
)

func TestNewIsUUIDv7AndSortable(t *testing.T) {
	prev := New()
	for i := 0; i < 1000; i++ {
		id := New()
		if !Valid(id) {
			t.Fatalf("generated invalid id %q", id)
		}
		if id < prev {
			t.Fatalf("ids not monotonic: %s < %s", id, prev)
		}
		prev = id
	}
	if Valid("01M2JKXF3AGSYGTC3TDHQMA2BA") {
		t.Fatal("a bare ULID string must not validate as an identifier")
	}
	if !Valid("0198b2f7-1a2b-7abc-9def-0123456789ab") {
		t.Fatal("a canonical UUIDv7 string should validate")
	}
}

func TestNewAtAndTime(t *testing.T) {
	ts := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	id := NewAt(ts)
	if !Valid(id) {
		t.Fatalf("NewAt produced invalid id %q", id)
	}
	got, err := Time(id)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(ts) {
		t.Fatalf("Time = %v, want %v", got, ts)
	}
	if _, err := Time("not-a-uuid"); err == nil {
		t.Fatal("expected error for malformed id")
	}
	if _, err := Time("00000000-0000-4000-8000-000000000000"); err == nil {
		t.Fatal("expected error for non-v7 uuid")
	}
}
