package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewExporterConfig(t *testing.T) {
	simulator, _ := NewSimulator(t, 35)
	tests := []struct {
		name                             string
		httpTimeout                      time.Duration
		rpcUrl                           string
		listenAddress                    string
		nodeKeys                         []string
		balanceAddresses                 []string
		comprehensiveSlotTracking        bool
		comprehensiveVoteAccountTracking bool
		monitorBlockSizes                bool
		lightMode                        bool
		slotPace                         time.Duration
		epochCleanupTime                 time.Duration
		wantErr                          bool
		expectedVoteKeys                 []string
		activeIdentity                   string
		firedancerMetricsPort            int
	}{
		{
			name:                             "valid configuration",
			httpTimeout:                      60 * time.Second,
			rpcUrl:                           simulator.Server.URL(),
			listenAddress:                    ":8080",
			nodeKeys:                         simulator.Nodekeys,
			balanceAddresses:                 []string{"xxx", "yyy", "zzz"},
			comprehensiveSlotTracking:        false,
			comprehensiveVoteAccountTracking: false,
			monitorBlockSizes:                false,
			lightMode:                        false,
			slotPace:                         time.Second,
			epochCleanupTime:                 60 * time.Second,
			wantErr:                          false,
			expectedVoteKeys:                 simulator.Votekeys,
			activeIdentity:                   simulator.Nodekeys[0],
			firedancerMetricsPort:            7999,
		},
		{
			name:                             "light mode with incompatible options",
			httpTimeout:                      60 * time.Second,
			rpcUrl:                           simulator.Server.URL(),
			listenAddress:                    ":8080",
			nodeKeys:                         simulator.Nodekeys,
			balanceAddresses:                 []string{"xxx", "yyy", "zzz"},
			comprehensiveSlotTracking:        false,
			comprehensiveVoteAccountTracking: false,
			monitorBlockSizes:                false,
			lightMode:                        true,
			slotPace:                         time.Second,
			epochCleanupTime:                 60 * time.Second,
			wantErr:                          true,
			expectedVoteKeys:                 nil,
			activeIdentity:                   simulator.Nodekeys[0],
			firedancerMetricsPort:            7999,
		},
		{
			name:                             "empty node keys",
			httpTimeout:                      60 * time.Second,
			rpcUrl:                           simulator.Server.URL(),
			listenAddress:                    ":8080",
			nodeKeys:                         []string{},
			balanceAddresses:                 []string{"xxx", "yyy", "zzz"},
			comprehensiveSlotTracking:        false,
			comprehensiveVoteAccountTracking: false,
			monitorBlockSizes:                false,
			lightMode:                        false,
			slotPace:                         time.Second,
			epochCleanupTime:                 60 * time.Second,
			wantErr:                          false,
			expectedVoteKeys:                 []string{},
			activeIdentity:                   simulator.Nodekeys[0],
			firedancerMetricsPort:            7999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewExporterConfig(
				context.Background(),
				tt.httpTimeout,
				tt.rpcUrl,
				tt.listenAddress,
				tt.nodeKeys,
				tt.balanceAddresses,
				tt.comprehensiveSlotTracking,
				tt.comprehensiveVoteAccountTracking,
				tt.monitorBlockSizes,
				tt.lightMode,
				tt.slotPace,
				tt.activeIdentity,
				tt.epochCleanupTime,
				tt.firedancerMetricsPort,
			)

			// Check error expectation
			if tt.wantErr {
				assert.Errorf(t, err, "NewExporterConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.NoError(t, err)

			// Verify config values
			assert.Equal(t, tt.httpTimeout, config.HttpTimeout)
			assert.Equal(t, tt.rpcUrl, config.RpcUrl)
			assert.Equal(t, tt.listenAddress, config.ListenAddress)
			assert.Equal(t, tt.nodeKeys, config.NodeKeys)
			assert.Equal(t, tt.balanceAddresses, config.BalanceAddresses)
			assert.Equal(t, tt.comprehensiveSlotTracking, config.ComprehensiveSlotTracking)
			assert.Equal(t, tt.comprehensiveVoteAccountTracking, config.ComprehensiveVoteAccountTracking)
			assert.Equal(t, tt.lightMode, config.LightMode)
			assert.Equal(t, tt.slotPace, config.SlotPace)
			assert.Equal(t, tt.epochCleanupTime, config.EpochCleanupTime)
			assert.Equal(t, tt.monitorBlockSizes, config.MonitorBlockSizes)
			assert.Equal(t, tt.expectedVoteKeys, config.VoteKeys)
			assert.Equal(t, tt.firedancerMetricsPort, config.FiredancerMetricsPort)
		})
	}
}
