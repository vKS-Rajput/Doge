package director

import (
	"testing"
)

func TestDirector_PolicyArbitration(t *testing.T) {
	d := NewDirector(0.60) // 60% exploit, 40% discover

	// First decision is discovery (bootstrapping unknown space)
	p1 := d.SelectPolicy()
	if p1 != PolicyDiscover {
		t.Fatalf("expected first policy to be PolicyDiscover, got %s", p1)
	}

	// Next decisions should balance out toward 60/40
	exploitCount := 0
	discoverCount := 1

	for i := 0; i < 9; i++ {
		p := d.SelectPolicy()
		if p == PolicyExploit {
			exploitCount++
		} else {
			discoverCount++
		}
	}

	t.Logf("10 selections: exploit=%d, discover=%d", exploitCount, discoverCount)
	if exploitCount == 0 {
		t.Fatal("expected at least one exploit selection")
	}

	// Test outcome recording
	d.RecordOutcome(PolicyDiscover, true, true)
	expStats, discStats, ratio := d.GetStats()

	if discStats.Novelties != 1 || discStats.FindingsFound != 1 {
		t.Fatalf("unexpected discovery stats: %+v", discStats)
	}
	_ = expStats
	_ = ratio
}
