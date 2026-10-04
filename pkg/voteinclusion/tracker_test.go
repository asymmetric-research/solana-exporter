package voteinclusion

import (
	"maps"
	"reflect"
	"testing"

	"github.com/asymmetric-research/solana-exporter/pkg/rpc"
)

// cluster simulates credits for a monitored account "me" and two references.
type cluster struct {
	tracker *Tracker
	rates   map[string]uint64
	credits map[string]uint64
	slot    int64
}

const (
	slotsPerEpoch = 1000
	epoch         = 5
	start         = epoch*slotsPerEpoch + 100 // well past the epoch-boundary window
)

func newCluster(t *testing.T, rateSamples int) *cluster {
	t.Helper()
	tracker := NewTracker(Config{Schedule: &rpc.EpochSchedule{SlotsPerEpoch: slotsPerEpoch}, RateSamples: rateSamples})
	tracker.SetAccounts([]string{"me"}, []string{"ref1", "ref2"})
	c := &cluster{
		tracker: tracker,
		rates:   map[string]uint64{"me": 600, "ref1": 7000, "ref2": 9000},
		credits: map[string]uint64{"me": 1e9, "ref1": 2e9, "ref2": 3e9},
		slot:    start,
	}
	for _, votekey := range tracker.Accounts() {
		tracker.SetLeaderSlots(votekey, epoch, nil)
	}
	if got := c.observe(); got != nil {
		t.Fatalf("first observation settled %+v, want nothing", got)
	}
	return c
}

// advance moves n slots; included[votekey] is how many of them credited votekey.
func (c *cluster) advance(n int64, included map[string]uint64) []Result {
	c.slot += n
	for votekey, k := range included {
		c.credits[votekey] += k * c.rates[votekey]
	}
	return c.observe()
}

func (c *cluster) observe() []Result {
	return c.tracker.Observe(Observation{Slot: c.slot, Credits: maps.Clone(c.credits)})
}

func TestTracker_CountsInclusionAndMisses(t *testing.T) {
	c := newCluster(t, 20)
	tests := []struct {
		name     string
		slots    int64
		included map[string]uint64
		want     Result
	}{
		{
			// one-slot gaps teach every account its rate immediately:
			name:     "one-slot gap",
			slots:    1,
			included: map[string]uint64{"me": 1, "ref1": 1, "ref2": 1},
			want:     Result{Included: 1, Expected: 1},
		},
		{
			name:     "partial inclusion",
			slots:    3,
			included: map[string]uint64{"me": 1, "ref1": 3, "ref2": 2},
			want:     Result{Included: 1, Expected: 3},
		},
		{
			name:     "validator down",
			slots:    5,
			included: map[string]uint64{"ref1": 5, "ref2": 5},
			want:     Result{Included: 0, Expected: 5},
		},
		{
			// nobody credited: no reward certificates, so nothing was missed.
			name:  "no certificates",
			slots: 2,
			want:  Result{Included: 0, Expected: 0},
		},
	}
	for _, tt := range tests {
		from := c.slot
		got := c.advance(tt.slots, tt.included)
		tt.want.Votekey, tt.want.From, tt.want.To = "me", from, c.slot
		if !reflect.DeepEqual(got, []Result{tt.want}) {
			t.Errorf("%s: got %+v, want %+v", tt.name, got, tt.want)
		}
	}
}

func TestTracker_UnattributedGaps(t *testing.T) {
	c := newCluster(t, 20)
	c.advance(1, map[string]uint64{"me": 1, "ref1": 1, "ref2": 1})
	all := func(n uint64) map[string]uint64 { return map[string]uint64{"me": n, "ref1": n, "ref2": n} }

	tests := []struct {
		name  string
		setup func()
		slots int64
		want  string
	}{
		{
			name: "own leader slot",
			setup: func() {
				c.tracker.SetLeaderSlots("me", epoch, []int64{c.slot + 2})
				c.credits["me"] += 12345 // leader reward
			},
			slots: 3,
			want:  ReasonLeader,
		},
		{
			name:  "credits not a multiple of the rate",
			setup: func() { c.credits["me"]++ },
			slots: 2,
			want:  ReasonAnomaly,
		},
		{
			name: "into the next epoch's reward-delay window",
			// jump so that the gap ends on the window's last slot:
			setup: func() { c.slot = (epoch+1)*slotsPerEpoch + RewardDelay - 2 },
			slots: 1,
			want:  ReasonEpochBoundary,
		},
		{
			name:  "new epoch without leader schedule",
			setup: func() {},
			slots: 10,
			want:  ReasonNoLeaderSchedule,
		},
	}
	for _, tt := range tests {
		tt.setup()
		got := c.advance(tt.slots, all(1))
		if len(got) != 1 || got[0].Reason != tt.want {
			t.Errorf("%s: got %+v, want reason %q", tt.name, got, tt.want)
		}
	}
}

func TestTracker_RateLearntFromGCD(t *testing.T) {
	c := newCluster(t, 3)

	// multi-slot gaps only, so results wait until each rate is learnt:
	gaps := []uint64{2, 3, 2}
	var got []Result
	for _, n := range gaps {
		got = append(got, c.advance(int64(n), map[string]uint64{"me": n, "ref1": n, "ref2": n})...)
	}
	if len(got) != len(gaps) {
		t.Fatalf("got %d results after %d credited gaps, want %d: %+v", len(got), len(gaps), len(gaps), got)
	}
	for i, r := range got {
		if r.Reason != "" || r.Included != gaps[i] || r.Expected != gaps[i] {
			t.Errorf("result %+v: want %d of %d included", r, gaps[i], gaps[i])
		}
	}
	if got, want := c.tracker.PerSlotReward("me", epoch), uint64(600); got != want {
		t.Errorf("PerSlotReward() = %d, want %d", got, want)
	}
}

func TestTracker_OutageBeforeRateKnown(t *testing.T) {
	c := newCluster(t, 20)
	// "me" is down from the start and never learns a rate; its gaps must still count as misses once the references
	// know theirs.
	got := c.advance(1, map[string]uint64{"ref1": 1, "ref2": 1})
	want := []Result{{Votekey: "me", From: start, To: start + 1, Included: 0, Expected: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
