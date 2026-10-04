package rpc

// minSlotsPerEpoch is the length of epoch 0 on a cluster with warmup (MINIMUM_SLOTS_PER_EPOCH).
const minSlotsPerEpoch = 32

// EpochSchedule is the result of getEpochSchedule.
type EpochSchedule struct {
	SlotsPerEpoch            int64 `json:"slotsPerEpoch"`
	LeaderScheduleSlotOffset int64 `json:"leaderScheduleSlotOffset"`
	Warmup                   bool  `json:"warmup"`
	FirstNormalEpoch         int64 `json:"firstNormalEpoch"`
	FirstNormalSlot          int64 `json:"firstNormalSlot"`
}

// GetEpoch returns the epoch containing slot.
func (s *EpochSchedule) GetEpoch(slot int64) int64 {
	if s.Warmup && slot < s.FirstNormalSlot {
		// warmup epochs double in length from minSlotsPerEpoch, so there are only a handful of them to walk:
		var epoch int64
		for s.GetFirstSlotInEpoch(epoch+1) <= slot {
			epoch++
		}
		return epoch
	}
	return s.FirstNormalEpoch + (slot-s.FirstNormalSlot)/s.SlotsPerEpoch
}

// GetFirstSlotInEpoch returns the first slot [inclusive] of epoch.
func (s *EpochSchedule) GetFirstSlotInEpoch(epoch int64) int64 {
	if s.Warmup && epoch <= s.FirstNormalEpoch {
		return (1<<epoch - 1) * minSlotsPerEpoch
	}
	return (epoch-s.FirstNormalEpoch)*s.SlotsPerEpoch + s.FirstNormalSlot
}
