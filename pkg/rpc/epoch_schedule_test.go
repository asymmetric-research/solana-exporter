package rpc

import "testing"

func TestEpochSchedule(t *testing.T) {
	warmup := EpochSchedule{SlotsPerEpoch: 8192, Warmup: true, FirstNormalEpoch: 8, FirstNormalSlot: 8160}
	testnet := EpochSchedule{SlotsPerEpoch: 432000, Warmup: true, FirstNormalEpoch: 14, FirstNormalSlot: 524256}
	flat := EpochSchedule{SlotsPerEpoch: 432000}
	tests := []struct {
		name      string
		schedule  EpochSchedule
		slot      int64
		wantEpoch int64
	}{
		{"warmup first slot", warmup, 0, 0},
		{"warmup end of epoch 0", warmup, 31, 0},
		{"warmup start of epoch 1", warmup, 32, 1},
		{"warmup end of epoch 1", warmup, 95, 1},
		{"warmup start of epoch 2", warmup, 96, 2},
		{"warmup last warmup slot", warmup, 8159, 7},
		{"warmup first normal slot", warmup, 8160, 8},
		{"warmup second normal epoch", warmup, 8160 + 8192, 9},
		{"testnet", testnet, 447759199, 1049},
		{"no warmup", flat, 447755972, 1036},
	}
	for _, tt := range tests {
		if got := tt.schedule.GetEpoch(tt.slot); got != tt.wantEpoch {
			t.Errorf("%s: GetEpoch(%d) = %d, want %d", tt.name, tt.slot, got, tt.wantEpoch)
		}
		first := tt.schedule.GetFirstSlotInEpoch(tt.wantEpoch)
		previousInSameEpoch := first > 0 && tt.schedule.GetEpoch(first-1) == tt.wantEpoch
		if first > tt.slot || tt.schedule.GetEpoch(first) != tt.wantEpoch || previousInSameEpoch {
			t.Errorf("%s: GetFirstSlotInEpoch(%d) = %d, not the first slot of the epoch containing %d",
				tt.name, tt.wantEpoch, first, tt.slot)
		}
	}
}
