// Package voteinclusion turns successive snapshots of vote-account credits into per-validator Alpenglow
// vote-inclusion counts.
//
// Under Alpenglow, block S carries the reward certificate for slot S-8. While replaying S, agave credits every
// validator present in that certificate with the same per-slot reward
//
//	r = floor(floor(maxValidatorReward * stake / (slotsPerEpoch * totalStake)) / 2)
//
// which is constant for a given validator within an epoch. Validators absent from the certificate are not touched.
// So between two observations at slots p < s, a validator's credits grow by exactly n*r, where n is the number of
// blocks in (p, s] whose reward certificate included it. Agave has already resolved the certificate bitmap against
// its own rank map; reading the credits back avoids having to rebuild that map.
//
// Two things break that arithmetic, and gaps containing them are reported as unattributed instead of counted:
//   - the validator's own leader slots, where it also earns a variable leader reward;
//   - the first RewardDelay slots of an epoch, whose rewards mix the previous epoch's stakes with the new epoch's
//     inflation.
//
// The tracker has no access to the certificates themselves, so the number of reward slots that could have included a
// validator is estimated as the largest n seen across all accounts with the same gap: well-connected reference
// validators make it into nearly every certificate, and a slot where none of them was credited had no reward
// certificate at all.
package voteinclusion

import (
	"slices"
	"sort"
	"strings"

	"github.com/asymmetric-research/solana-exporter/pkg/rpc"
)

// RewardDelay is agave's NUM_SLOTS_FOR_REWARD: block S rewards slot S-RewardDelay.
const RewardDelay = 8

// Reasons for which a gap is not attributed.
const (
	ReasonLeader           = "leader"
	ReasonEpochBoundary    = "epoch_boundary"
	ReasonNoLeaderSchedule = "no_leader_schedule"
	ReasonRateUnknown      = "rate_unknown"
	ReasonAnomaly          = "anomaly"
)

type (
	// Observation is the cumulative vote credits of each account as of Slot. All accounts must be read in a single
	// RPC call so that they share one bank.
	Observation struct {
		Slot    int64
		Credits map[string]uint64
	}

	// Result reports what happened to a monitored vote account in the slots (From, To].
	Result struct {
		Votekey  string
		From, To int64
		// Reason is set when the slots could not be attributed; Included and Expected are then zero.
		Reason string
		// Included is the number of reward slots in which the account was credited.
		Included uint64
		// Expected is the number of reward slots in the gap, estimated across all accounts. Expected-Included
		// were missed.
		Expected uint64
	}

	// Config configures a Tracker.
	Config struct {
		Schedule *rpc.EpochSchedule
		// RateSamples is how many credited gaps an account needs before its per-slot reward is taken as the GCD of
		// their deltas. A single-slot gap settles it immediately.
		RateSamples int
		// MaxPending bounds how many gaps wait for per-slot rewards to be learnt.
		MaxPending int
	}

	// Tracker is not safe for concurrent use.
	Tracker struct {
		config   Config
		accounts map[string]*account
		pending  []*gap
	}

	account struct {
		votekey   string
		monitored bool

		seen        bool
		lastSlot    int64
		lastCredits uint64

		// leaderSlots holds sorted absolute leader slots per epoch.
		leaderSlots map[int64][]int64
		rates       map[int64]*rate
	}

	// rate learns an account's per-slot reward within one epoch.
	rate struct {
		gcd     uint64
		samples int
		perSlot uint64 // 0 until learnt
	}

	sample struct {
		account *account
		from    int64
		delta   uint64
		reason  string
	}

	gap struct {
		to      int64
		epoch   int64
		samples []sample
	}
)

// NewTracker returns a Tracker with no accounts. Zero RateSamples and MaxPending get defaults.
func NewTracker(config Config) *Tracker {
	if config.RateSamples <= 0 {
		config.RateSamples = 20
	}
	if config.MaxPending <= 0 {
		config.MaxPending = 1000
	}
	return &Tracker{config: config, accounts: make(map[string]*account)}
}

// SetAccounts replaces the tracked accounts. Accounts kept across calls keep their history. A votekey in both lists
// is treated as monitored.
func (t *Tracker) SetAccounts(monitored, references []string) {
	next := make(map[string]*account)
	add := func(votekey string, isMonitored bool) {
		a, ok := t.accounts[votekey]
		if !ok {
			a = &account{votekey: votekey, leaderSlots: make(map[int64][]int64), rates: make(map[int64]*rate)}
		}
		a.monitored = isMonitored
		next[votekey] = a
	}
	for _, votekey := range references {
		add(votekey, false)
	}
	// monitored last, so that an account in both lists ends up monitored:
	for _, votekey := range monitored {
		add(votekey, true)
	}
	t.accounts = next
}

// Accounts returns the tracked votekeys, sorted.
func (t *Tracker) Accounts() []string {
	votekeys := make([]string, 0, len(t.accounts))
	for votekey := range t.accounts {
		votekeys = append(votekeys, votekey)
	}
	slices.Sort(votekeys)
	return votekeys
}

// HasLeaderSchedule reports whether SetLeaderSlots was called for votekey and epoch.
func (t *Tracker) HasLeaderSchedule(votekey string, epoch int64) bool {
	a, ok := t.accounts[votekey]
	if !ok {
		return false
	}
	_, ok = a.leaderSlots[epoch]
	return ok
}

// SetLeaderSlots records the absolute slots in epoch led by votekey's node.
func (t *Tracker) SetLeaderSlots(votekey string, epoch int64, slots []int64) {
	a, ok := t.accounts[votekey]
	if !ok {
		return
	}
	sorted := slices.Clone(slots)
	slices.Sort(sorted)
	a.leaderSlots[epoch] = sorted
	for e := range a.leaderSlots {
		if e+1 < epoch {
			delete(a.leaderSlots, e)
		}
	}
}

// PerSlotReward returns votekey's learnt per-slot reward (in credits) in epoch, or 0 if not learnt yet.
func (t *Tracker) PerSlotReward(votekey string, epoch int64) uint64 {
	if a, ok := t.accounts[votekey]; ok {
		return a.perSlot(epoch)
	}
	return 0
}

// Pending returns how many gaps are waiting for per-slot rewards to be learnt.
func (t *Tracker) Pending() int { return len(t.pending) }

// Observe records a snapshot and returns results for every gap that could be settled, oldest first.
func (t *Tracker) Observe(observation Observation) []Result {
	g := &gap{to: observation.Slot, epoch: t.config.Schedule.GetEpoch(observation.Slot)}
	for votekey, credits := range observation.Credits {
		a, ok := t.accounts[votekey]
		if !ok {
			continue
		}
		if a.seen && observation.Slot <= a.lastSlot {
			// stale RPC node; keep the newer baseline:
			continue
		}
		if a.seen {
			s := sample{account: a, from: a.lastSlot}
			if credits < a.lastCredits {
				s.reason = ReasonAnomaly
			} else {
				s.delta = credits - a.lastCredits
				s.reason = t.classify(a, s.from, observation.Slot)
			}
			if s.reason == "" {
				t.learn(a, g.epoch, s.delta, observation.Slot-s.from)
			}
			g.samples = append(g.samples, s)
		}
		a.seen, a.lastSlot, a.lastCredits = true, observation.Slot, credits
	}
	if len(g.samples) > 0 {
		t.pending = append(t.pending, g)
	}
	return t.settleReady()
}

// classify returns why the slots (from, to] can't be counted for a, or "" if they can.
func (t *Tracker) classify(a *account, from, to int64) string {
	schedule := t.config.Schedule
	epoch := schedule.GetEpoch(to)
	if schedule.GetEpoch(from+1) != epoch || from+1 < schedule.GetFirstSlotInEpoch(epoch)+RewardDelay {
		return ReasonEpochBoundary
	}
	leaderSlots, ok := a.leaderSlots[epoch]
	if !ok {
		return ReasonNoLeaderSchedule
	}
	// the gap is tainted if the first leader slot after 'from' is within it:
	i := sort.Search(len(leaderSlots), func(i int) bool { return leaderSlots[i] > from })
	if i < len(leaderSlots) && leaderSlots[i] <= to {
		return ReasonLeader
	}
	return ""
}

func (t *Tracker) learn(a *account, epoch int64, delta uint64, slots int64) {
	r, ok := a.rates[epoch]
	if !ok {
		r = &rate{}
		a.rates[epoch] = r
		for e := range a.rates {
			if e+1 < epoch {
				delete(a.rates, e)
			}
		}
	}
	if r.perSlot != 0 || delta == 0 {
		return
	}
	r.gcd = gcd(r.gcd, delta)
	r.samples++
	// a one-slot gap credits exactly one reward. Otherwise, once enough gaps of mixed lengths have been credited,
	// their GCD is the per-slot reward:
	if slots == 1 || r.samples >= t.config.RateSamples {
		r.perSlot = r.gcd
	}
}

func (t *Tracker) settleReady() []Result {
	var results []Result
	for len(t.pending) > 0 {
		g := t.pending[0]
		if !t.ready(g) && len(t.pending) <= t.config.MaxPending {
			break
		}
		t.pending = t.pending[1:]
		results = append(results, t.settle(g)...)
	}
	return results
}

// ready reports whether every monitored account in g can be counted and, if any reference account could be
// counted, at least one of them can.
func (t *Tracker) ready(g *gap) bool {
	referenceCounted, referenceKnown := false, false
	for _, s := range g.samples {
		if s.reason != "" {
			continue
		}
		// an uncredited gap counts as zero inclusions without knowing the rate:
		known := s.delta == 0 || s.account.perSlot(g.epoch) != 0
		if s.account.monitored && !known {
			return false
		}
		if !s.account.monitored {
			referenceCounted = true
			referenceKnown = referenceKnown || known
		}
	}
	return !referenceCounted || referenceKnown
}

func (t *Tracker) settle(g *gap) []Result {
	type count struct {
		n      uint64
		reason string
	}
	counts := make([]count, len(g.samples))
	expected := make(map[int64]uint64) // from-slot -> max n across accounts
	for i, s := range g.samples {
		c := count{reason: s.reason}
		// Observe only records gaps that moved forward, so this is always positive:
		var gapSlots uint64
		if d := g.to - s.from; d > 0 {
			gapSlots = uint64(d) //nolint:gosec // G115: d > 0 is checked above
		}
		if c.reason == "" {
			perSlot := s.account.perSlot(g.epoch)
			switch {
			case s.delta == 0:
				// not credited: n is 0 whatever the rate.
			case perSlot == 0:
				c.reason = ReasonRateUnknown
			case s.delta%perSlot != 0 || s.delta/perSlot > gapSlots:
				c.reason = ReasonAnomaly
			default:
				c.n = s.delta / perSlot
				expected[s.from] = max(expected[s.from], c.n)
			}
		}
		counts[i] = c
	}

	var results []Result
	for i, s := range g.samples {
		if !s.account.monitored {
			continue
		}
		result := Result{Votekey: s.account.votekey, From: s.from, To: g.to, Reason: counts[i].reason}
		if result.Reason == "" {
			result.Included, result.Expected = counts[i].n, expected[s.from]
		}
		results = append(results, result)
	}
	slices.SortFunc(results, func(a, b Result) int { return strings.Compare(a.Votekey, b.Votekey) })
	return results
}

func (a *account) perSlot(epoch int64) uint64 {
	if r, ok := a.rates[epoch]; ok {
		return r.perSlot
	}
	return 0
}

func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
