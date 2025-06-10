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
		nodekeys                         []string
		votekeys                         []string
		balanceAddresses                 []string
		comprehensiveSlotTracking        bool
		comprehensiveVoteAccountTracking bool
		monitorBlockSizes                bool
		lightMode                        bool
		slotPace                         time.Duration
		epochCleanupTime                 time.Duration
		wantErr                          bool
		expectedNodekeys                 []string
		expectedVotekeys                 []string
		activeIdentity                   string
	}{
		{
			name:                             "valid configuration",
			httpTimeout:                      60 * time.Second,
			rpcUrl:                           simulator.Server.URL(),
			listenAddress:                    ":8080",
			nodekeys:                         simulator.Nodekeys,
			votekeys:                         simulator.Votekeys,
			balanceAddresses:                 []string{"xxx", "yyy", "zzz"},
			comprehensiveSlotTracking:        false,
			comprehensiveVoteAccountTracking: false,
			monitorBlockSizes:                false,
			lightMode:                        false,
			slotPace:                         time.Second,
			epochCleanupTime:                 60 * time.Second,
			wantErr:                          false,
			expectedNodekeys:                 simulator.Nodekeys,
			expectedVotekeys:                 simulator.Votekeys,
			activeIdentity:                   simulator.Nodekeys[0],
		},
		{
			name:                             "light mode with incompatible options",
			httpTimeout:                      60 * time.Second,
			rpcUrl:                           simulator.Server.URL(),
			listenAddress:                    ":8080",
			nodekeys:                         simulator.Nodekeys,
			votekeys:                         simulator.Votekeys,
			balanceAddresses:                 []string{"xxx", "yyy", "zzz"},
			comprehensiveSlotTracking:        false,
			comprehensiveVoteAccountTracking: false,
			monitorBlockSizes:                false,
			lightMode:                        true,
			slotPace:                         time.Second,
			epochCleanupTime:                 60 * time.Second,
			wantErr:                          true,
			expectedNodekeys:                 nil,
			expectedVotekeys:                 nil,
			activeIdentity:                   simulator.Nodekeys[0],
		},
		{
			name:                             "empty node keys",
			httpTimeout:                      60 * time.Second,
			rpcUrl:                           simulator.Server.URL(),
			listenAddress:                    ":8080",
			nodekeys:                         []string{},
			votekeys:                         []string{},
			balanceAddresses:                 []string{"xxx", "yyy", "zzz"},
			comprehensiveSlotTracking:        false,
			comprehensiveVoteAccountTracking: false,
			monitorBlockSizes:                false,
			lightMode:                        false,
			slotPace:                         time.Second,
			epochCleanupTime:                 60 * time.Second,
			wantErr:                          false,
			expectedNodekeys:                 nil,
			expectedVotekeys:                 nil,
			activeIdentity:                   simulator.Nodekeys[0],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewExporterConfig(
				context.Background(),
				tt.httpTimeout,
				tt.rpcUrl,
				tt.listenAddress,
				tt.nodekeys,
				tt.votekeys,
				tt.balanceAddresses,
				tt.comprehensiveSlotTracking,
				tt.comprehensiveVoteAccountTracking,
				tt.monitorBlockSizes,
				tt.lightMode,
				tt.slotPace,
				tt.activeIdentity,
				tt.epochCleanupTime,
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
			assert.Equal(t, tt.expectedNodekeys, config.Nodekeys)
			assert.Equal(t, tt.expectedVotekeys, config.Votekeys)
			assert.Equal(t, tt.balanceAddresses, config.BalanceAddresses)
			assert.Equal(t, tt.comprehensiveSlotTracking, config.ComprehensiveSlotTracking)
			assert.Equal(t, tt.comprehensiveVoteAccountTracking, config.ComprehensiveVoteAccountTracking)
			assert.Equal(t, tt.lightMode, config.LightMode)
			assert.Equal(t, tt.slotPace, config.SlotPace)
			assert.Equal(t, tt.epochCleanupTime, config.EpochCleanupTime)
			assert.Equal(t, tt.monitorBlockSizes, config.MonitorBlockSizes)
		})
	}
}
