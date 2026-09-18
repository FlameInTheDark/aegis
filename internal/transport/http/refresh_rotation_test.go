package httpx

import (
	"context"
	"errors"
	"testing"
)

type rotationRecorder struct {
	id, presented, successor string
	err                      error
}

func (r *rotationRecorder) Rotate(_ context.Context, id, presentedHash, newHash string) error {
	r.id, r.presented, r.successor = id, presentedHash, newHash
	return r.err
}

func TestPersistRefreshRotation(t *testing.T) {
	storageError := errors.New("storage unavailable")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "success"},
		{name: "storage failure", err: storageError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &rotationRecorder{err: tc.err}
			presented := hashRefresh("previous synthetic token")
			const successor = "new synthetic token"
			err := persistRefreshRotation(t.Context(), store, "session-id", presented, successor)
			if !errors.Is(err, tc.err) {
				t.Fatalf("error = %v, want %v", err, tc.err)
			}
			if store.id != "session-id" || store.presented != presented {
				t.Fatal("session identity or presented hash changed")
			}
			if store.successor != hashRefresh(successor) || store.successor == successor {
				t.Fatal("successor must cross the persistence boundary as a hash")
			}
		})
	}
}
