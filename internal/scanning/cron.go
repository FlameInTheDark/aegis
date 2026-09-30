package scanning

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The documented schedule grammar (docs/SPEC-COMPLIANCE.md): a five-field
// cron expression (minute hour day-of-month month day-of-week) with classic
// Vixie semantics, or the "@every <duration>" interval form.
//
// Per field: "*", lists ("a,b"), ranges ("a-b"), steps ("*/15", "9-17/2"),
// and month/weekday names ("jan", "mon"). Day-of-week accepts 0-7 with both
// 0 and 7 meaning Sunday. When both day-of-month and day-of-week are
// restricted the union matches (classic cron); when only one is restricted,
// it must match. Ranges never wrap ("fri-mon" is an error); DST transitions
// follow Go's time.Date normalization.

type cronField struct {
	bits       uint64
	restricted bool // false only when the field covers its full range
}

func (f cronField) has(v int) bool { return f.bits&(1<<uint(v)) != 0 }

var cronMonthNames = map[string]int{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
	"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

var cronDOWNames = map[string]int{
	"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
}

// CronSpec is a parsed schedule expression.
type CronSpec struct {
	minute, hour cronField // 0-59 / 0-23
	dom, month   cronField // 1-31 / 1-12
	dow          cronField // 0-7, 7 normalized to 0 (Sunday)
	every        time.Duration
}

// ParseCron parses and validates a schedule expression.
func ParseCron(expr string) (*CronSpec, error) {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "@every ") {
		d, err := time.ParseDuration(strings.TrimSpace(expr[len("@every "):]))
		if err != nil {
			return nil, fmt.Errorf("invalid @every duration: %w", err)
		}
		if d < time.Minute {
			return nil, errors.New("@every duration must be at least 1m")
		}
		return &CronSpec{every: d}, nil
	}
	if strings.HasPrefix(expr, "@") {
		return nil, fmt.Errorf("unsupported schedule descriptor %q", expr)
	}
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("expected 5 cron fields (minute hour day-of-month month day-of-week), got %d", len(fields))
	}
	minute, err := parseCronField(fields[0], 0, 59, nil, false)
	if err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	hour, err := parseCronField(fields[1], 0, 23, nil, false)
	if err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	dom, err := parseCronField(fields[2], 1, 31, nil, false)
	if err != nil {
		return nil, fmt.Errorf("day-of-month: %w", err)
	}
	month, err := parseCronField(fields[3], 1, 12, cronMonthNames, false)
	if err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	dow, err := parseCronField(fields[4], 0, 7, cronDOWNames, true)
	if err != nil {
		return nil, fmt.Errorf("day-of-week: %w", err)
	}
	return &CronSpec{minute: minute, hour: hour, dom: dom, month: month, dow: dow}, nil
}

// ValidateCron reports whether expr is a supported schedule expression.
func ValidateCron(expr string) error {
	_, err := ParseCron(expr)
	return err
}

func parseCronValue(tok string, names map[string]int) (int, error) {
	if v, err := strconv.Atoi(tok); err == nil {
		return v, nil
	}
	if names != nil {
		if v, ok := names[strings.ToLower(tok)]; ok {
			return v, nil
		}
	}
	return 0, fmt.Errorf("invalid value %q", tok)
}

func parseCronField(spec string, min, max int, names map[string]int, dow bool) (cronField, error) {
	var out cronField
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return out, errors.New("empty field")
	}
	for _, part := range strings.Split(spec, ",") {
		if part == "" {
			return out, fmt.Errorf("empty list item in %q", spec)
		}
		step := 1
		if i := strings.Index(part, "/"); i >= 0 {
			s, err := strconv.Atoi(part[i+1:])
			if err != nil || s < 1 {
				return out, fmt.Errorf("invalid step in %q", part)
			}
			step = s
			part = part[:i]
		}
		lo, hi := min, max
		if part != "*" {
			bounds := strings.SplitN(part, "-", 2)
			var err error
			lo, err = parseCronValue(bounds[0], names)
			if err != nil {
				return out, err
			}
			hi = lo
			if len(bounds) == 2 {
				hi, err = parseCronValue(bounds[1], names)
				if err != nil {
					return out, err
				}
			}
			if lo < min || hi > max || lo > hi {
				return out, fmt.Errorf("value out of range %d-%d in %q", min, max, part)
			}
		}
		for v := lo; ; v += step {
			bit := v
			if dow && bit == 7 {
				bit = 0
			}
			out.bits |= 1 << uint(bit)
			if v >= hi {
				break
			}
		}
		if !(step == 1 && lo == min && hi == max) {
			out.restricted = true
		}
	}
	return out, nil
}

func (s *CronSpec) dayMatches(t time.Time) bool {
	domOK := !s.dom.restricted || s.dom.has(t.Day())
	dowOK := !s.dow.restricted || s.dow.has(int(t.Weekday()))
	if s.dom.restricted && s.dow.restricted {
		return domOK || dowOK
	}
	return domOK && dowOK
}

// NextAfter returns the first run strictly after t, or the zero time when no
// run exists within the five-year search horizon (e.g. Feb 29 with no leap
// day in range).
func (s *CronSpec) NextAfter(after time.Time) time.Time {
	if s.every > 0 {
		return after.Add(s.every)
	}
	t := after.Truncate(time.Minute).Add(time.Minute)
	afterY, afterM, afterD := after.Date()
	limit := after.AddDate(5, 0, 0)
	for t.Before(limit) {
		if !s.month.has(int(t.Month())) || !s.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location()).AddDate(0, 0, 1)
			continue
		}
		sameDay := false
		startH, startM := 0, 0
		if y, m, d := t.Date(); y == afterY && m == afterM && d == afterD {
			sameDay = true
			startH, startM = t.Hour(), t.Minute()
		}
		for h := startH; h < 24; h++ {
			if !s.hour.has(h) {
				continue
			}
			mLo := 0
			if h == startH && sameDay {
				mLo = startM
			}
			for m := mLo; m < 60; m++ {
				if !s.minute.has(m) {
					continue
				}
				next := time.Date(t.Year(), t.Month(), t.Day(), h, m, 0, 0, t.Location())
				if next.After(after) {
					return next
				}
			}
		}
		t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location()).AddDate(0, 0, 1)
	}
	return time.Time{}
}

// NextRunsAfter computes the next n run times of expr at or after now.
// Invalid expressions return an error so callers can surface bad schedules
// before they are saved.
func NextRunsAfter(now time.Time, expr string, n int) ([]time.Time, error) {
	spec, err := ParseCron(expr)
	if err != nil {
		return nil, err
	}
	out := make([]time.Time, 0, n)
	t := now
	for i := 0; i < n; i++ {
		next := spec.NextAfter(t)
		if next.IsZero() {
			break
		}
		out = append(out, next)
		t = next
	}
	return out, nil
}
