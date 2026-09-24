// Package redis implements cache, rate limiting, distributed locks,
// deduplication windows and short-lived state. Redis is never the
// authoritative store for assets, vulnerabilities or events.
package redisrepo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/FlameInTheDark/aegis/internal/observability"
)

// Client wraps go-redis.
type Client struct{ rdb *redis.Client }

// Connect parses a redis:// URL.
func Connect(ctx context.Context, url string) (*Client, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("redis: parse url: %w", err)
	}
	opts.DialTimeout = 3 * time.Second
	rdb := redis.NewClient(opts)
	if err := rdb.Ping(ctx).Err(); err != nil {
		rdb.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}
	return &Client{rdb: rdb}, nil
}

// CacheGet returns a cached JSON value.
func (c *Client) CacheGet(ctx context.Context, key string, out any) (bool, error) {
	b, err := c.rdb.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return false, nil // treat corrupt entries as misses
	}
	return true, nil
}

// CacheSet stores a JSON value with TTL.
func (c *Client) CacheSet(ctx context.Context, key string, val any, ttl time.Duration) error {
	b, err := json.Marshal(val)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, key, b, ttl).Err()
}

// CacheInvalidate deletes keys.
func (c *Client) CacheInvalidate(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	return c.rdb.Del(ctx, keys...).Err()
}

// RateLimit implements a fixed-window counter. Returns allowed=true when
// the caller is under the limit.
func (c *Client) RateLimit(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, remaining int, err error) {
	pipe := c.rdb.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.ExpireNX(ctx, key, window)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, 0, err
	}
	n := int(incr.Val())
	return n <= limit, max(0, limit-n), nil
}

// Lock acquires a distributed lock (SET NX EX). Returns a release func.
func (c *Client) Lock(ctx context.Context, key string, ttl time.Duration) (func(), bool, error) {
	token := fmt.Sprintf("lock:%d", time.Now().UnixNano())
	ok, err := c.rdb.SetNX(ctx, key, token, ttl).Result()
	if err != nil || !ok {
		return func() {}, false, err
	}
	release := func() {
		// Release only if we still own the lock (token check).
		const script = `if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end`
		_ = c.rdb.Eval(ctx, script, []string{key}, token)
	}
	return release, true, nil
}

// DedupCheck marks an idempotency key as seen within the window and reports
// whether this is the first occurrence.
func (c *Client) DedupCheck(ctx context.Context, key string, window time.Duration) (first bool, err error) {
	ok, err := c.rdb.SetNX(ctx, "dedup:"+key, 1, window).Result()
	return ok, err
}

// JobDedupKey builds the documented idempotency key formats.
func JobDedupKey(parts ...string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ":"
		}
		out += p
	}
	return out
}

// SetTTL stores a raw string with TTL (scan progress etc.).
func (c *Client) SetTTL(ctx context.Context, key, val string, ttl time.Duration) error {
	return c.rdb.Set(ctx, key, val, ttl).Err()
}

// GetTTL reads a raw string.
func (c *Client) GetTTL(ctx context.Context, key string) (string, bool, error) {
	s, err := c.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	return s, err == nil, err
}

// Publish issues a pub/sub message (live UI updates).
func (c *Client) Publish(ctx context.Context, channel string, payload []byte) error {
	return c.rdb.Publish(ctx, channel, payload).Err()
}

// Subscribe subscribes to a channel.
func (c *Client) Subscribe(ctx context.Context, channel string) *redis.PubSub {
	return c.rdb.Subscribe(ctx, channel)
}

// Health implements observability.Checker.
func (c *Client) CheckHealth(ctx context.Context) observability.DependencyHealth {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := c.rdb.Ping(ctx).Err(); err != nil {
		return observability.DependencyHealth{Name: "redis", Status: "down", Detail: err.Error()}
	}
	return observability.DependencyHealth{Name: "redis", Status: "ok"}
}

// Close closes the connection.
func (c *Client) Close() error { return c.rdb.Close() }

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
