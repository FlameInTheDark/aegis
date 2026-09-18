package scanning

import "time"

func timeDate(y, mo, d, h, min int) time.Time {
	return time.Date(y, time.Month(mo), d, h, min, 0, 0, time.UTC)
}
