package store

import (
	"testing"
	"time"
)

func TestRetentionExpiryClampsToLastDayOfTargetMonth(t *testing.T) {
	input := time.Date(2024, time.February, 29, 12, 30, 15, 123, time.FixedZone("offset", 3600))
	got := retentionExpiry(input)
	want := time.Date(2026, time.February, 28, 11, 30, 15, 123, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("retentionExpiry(%s) = %s, want %s", input, got, want)
	}
}
