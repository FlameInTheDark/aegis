package httpx

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// PageQuery is offset pagination for small administrative lists.
type PageQuery struct {
	Page   int    `json:"page"`
	Limit  int    `json:"limit"`
	Sort   string `json:"sort"`
	Order  string `json:"order"`
	Search string `json:"search"`
}

// CursorQuery is cursor pagination for large datasets: events, assets,
// findings, services.
type CursorQuery struct {
	Cursor string `json:"cursor"`
	Limit  int    `json:"limit"`
	Search string `json:"search"`
}

const (
	defaultPage  = 1
	defaultLimit = 50
	maxLimit     = 200
)

// ParsePageQuery reads offset pagination parameters.
func ParsePageQuery(c *fiber.Ctx) PageQuery {
	q := PageQuery{
		Page:   atoiOr(c.Query("page"), defaultPage),
		Limit:  atoiOr(c.Query("limit"), defaultLimit),
		Sort:   c.Query("sort"),
		Order:  strings.ToLower(c.Query("order")),
		Search: strings.TrimSpace(c.Query("q")),
	}
	if q.Page < 1 {
		q.Page = defaultPage
	}
	if q.Limit < 1 {
		q.Limit = defaultLimit
	}
	if q.Limit > maxLimit {
		q.Limit = maxLimit
	}
	if q.Order != "asc" {
		q.Order = "desc"
	}
	return q
}

// ParseCursorQuery reads cursor pagination parameters.
func ParseCursorQuery(c *fiber.Ctx) CursorQuery {
	q := CursorQuery{
		Cursor: c.Query("cursor"),
		Limit:  atoiOr(c.Query("limit"), defaultLimit),
		Search: strings.TrimSpace(c.Query("q")),
	}
	if q.Limit < 1 {
		q.Limit = defaultLimit
	}
	if q.Limit > maxLimit {
		q.Limit = maxLimit
	}
	return q
}

// Page[T] is an offset-paginated response envelope.
type Page[T any] struct {
	Items      []T   `json:"items"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	TotalPages int64 `json:"total_pages"`
}

// NewPage builds a page response.
func NewPage[T any](items []T, total int64, q PageQuery) Page[T] {
	tp := (total + int64(q.Limit) - 1) / int64(q.Limit)
	if tp < 1 {
		tp = 1
	}
	return Page[T]{Items: items, Total: total, Page: q.Page, Limit: q.Limit, TotalPages: tp}
}

// CursorPage[T] is a cursor-paginated response envelope.
type CursorPage[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"has_more"`
}

// NewCursorPage builds a cursor page from a window of limit+1 items.
func NewCursorPage[T any](items []T, limit int, cursorOf func(T) string) CursorPage[T] {
	hasMore := false
	if len(items) > limit {
		items = items[:limit]
		hasMore = true
	}
	var next string
	if hasMore && len(items) > 0 {
		next = cursorOf(items[len(items)-1])
	}
	return CursorPage[T]{Items: items, NextCursor: next, HasMore: hasMore}
}

// DecodeCursor decodes an opaque "ulid:extra" cursor.
func DecodeCursor(s string) (id string, extra string, err error) {
	if s == "" {
		return "", "", nil
	}
	parts := strings.SplitN(s, ":", 2)
	if parts[0] == "" {
		return "", "", fmt.Errorf("invalid cursor")
	}
	id = parts[0]
	if len(parts) == 2 {
		extra = parts[1]
	}
	return id, extra, nil
}

func atoiOr(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
