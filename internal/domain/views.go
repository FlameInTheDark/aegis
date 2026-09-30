package domain

import "time"

// SavedView is a named query string a user pinned for one console page
// (F12): the exact hash-router query the page was filtered with, restorable
// in one click. Views are strictly per user — sharing is a later flag.
type SavedView struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"organization_id"`
	UserID    string    `json:"user_id"`
	Page      string    `json:"page"` // assets | findings | alerts
	Name      string    `json:"name"`
	Query     string    `json:"query"`
	CreatedAt time.Time `json:"created_at"`
}

// SavedViewPages is the allowlist of console pages a view can attach to.
var SavedViewPages = []string{"assets", "findings", "alerts"}

// ValidSavedViewPage reports whether page is a console page views may pin.
func ValidSavedViewPage(page string) bool {
	for _, p := range SavedViewPages {
		if p == page {
			return true
		}
	}
	return false
}
