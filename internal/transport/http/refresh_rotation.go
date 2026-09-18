package httpx

import "context"

// refreshRotator accepts hashes only; the HTTP layer owns raw cookie tokens.
type refreshRotator interface {
	Rotate(ctx context.Context, id, presentedHash, newHash string) error
}

// persistRefreshRotation keeps raw successor tokens out of session storage.
func persistRefreshRotation(ctx context.Context, store refreshRotator, sessionID, presentedHash, successorToken string) error {
	return store.Rotate(ctx, sessionID, presentedHash, hashRefresh(successorToken))
}
