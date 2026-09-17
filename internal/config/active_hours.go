package config

import (
	"fmt"
	"strconv"
	"strings"
)

const minutesPerDay = 24 * 60

// ActiveHours is a daily window in a credential's local time. Start and End are
// minutes since midnight; End at or before Start means the window wraps past
// midnight (08:30-01:00 runs from 08:30 today to 01:00 tomorrow). The zero value
// means no restriction.
type ActiveHours struct {
	Start int
	End   int
	set   bool
}

// ParseActiveHours parses "HH:MM-HH:MM". Empty or "always" means no restriction.
func ParseActiveHours(raw string) (ActiveHours, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "always") {
		return ActiveHours{}, nil
	}
	parts := strings.Split(raw, "-")
	if len(parts) != 2 {
		return ActiveHours{}, fmt.Errorf("active-hours %q: want HH:MM-HH:MM", raw)
	}
	start, errStart := parseClockMinutes(parts[0])
	if errStart != nil {
		return ActiveHours{}, fmt.Errorf("active-hours %q: %w", raw, errStart)
	}
	end, errEnd := parseClockMinutes(parts[1])
	if errEnd != nil {
		return ActiveHours{}, fmt.Errorf("active-hours %q: %w", raw, errEnd)
	}
	if start == end {
		return ActiveHours{}, fmt.Errorf("active-hours %q: start and end are equal; leave it empty for always-on", raw)
	}
	return ActiveHours{Start: start, End: end, set: true}, nil
}

func parseClockMinutes(raw string) (int, error) {
	fields := strings.Split(strings.TrimSpace(raw), ":")
	if len(fields) != 2 {
		return 0, fmt.Errorf("%q is not HH:MM", raw)
	}
	hour, errHour := strconv.Atoi(fields[0])
	minute, errMinute := strconv.Atoi(fields[1])
	if errHour != nil || errMinute != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("%q is not HH:MM", raw)
	}
	return hour*60 + minute, nil
}

// IsZero reports whether no window is set (always on).
func (h ActiveHours) IsZero() bool { return !h.set }

// Wraps reports whether the window crosses local midnight.
func (h ActiveHours) Wraps() bool { return h.set && h.End <= h.Start }

// Minutes returns the window length in minutes.
func (h ActiveHours) Minutes() int {
	switch {
	case !h.set:
		return minutesPerDay
	case h.Wraps():
		return minutesPerDay - h.Start + h.End
	default:
		return h.End - h.Start
	}
}

// String renders the window as HH:MM-HH:MM, or "" when always on.
func (h ActiveHours) String() string {
	if !h.set {
		return ""
	}
	return fmt.Sprintf("%02d:%02d-%02d:%02d", h.Start/60, h.Start%60, h.End/60, h.End%60)
}
