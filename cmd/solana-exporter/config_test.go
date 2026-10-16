package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewExporterConfig(t *testing.T) {
	simulator, _ := NewSimulator(t, 35)
	tests := []struct {
		name                             string
		httpTimeout                      time.Duration
		rpcURL                           string
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
			rpcURL:                           simulator.Server.URL(),
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
			rpcURL:                           simulator.Server.URL(),
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
			rpcURL:                           simulator.Server.URL(),
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
		{
			name:                             "duplicate votekeys",
			httpTimeout:                      60 * time.Second,
			rpcURL:                           simulator.Server.URL(),
			listenAddress:                    ":8080",
			nodekeys:                         []string{},
			votekeys:                         []string{simulator.Votekeys[0], simulator.Votekeys[0]},
			balanceAddresses:                 []string{},
			comprehensiveSlotTracking:        false,
			comprehensiveVoteAccountTracking: false,
			monitorBlockSizes:                false,
			lightMode:                        false,
			slotPace:                         time.Second,
			epochCleanupTime:                 60 * time.Second,
			wantErr:                          true,
			expectedNodekeys:                 nil,
			expectedVotekeys:                 nil,
			activeIdentity:                   simulator.Nodekeys[0],
		},
		{
			name:                             "valid light mode configuration",
			httpTimeout:                      60 * time.Second,
			rpcURL:                           "http://invalid-rpc:9999",
			listenAddress:                    ":8080",
			nodekeys:                         []string{},
			votekeys:                         []string{},
			balanceAddresses:                 []string{},
			comprehensiveSlotTracking:        false,
			comprehensiveVoteAccountTracking: false,
			monitorBlockSizes:                false,
			lightMode:                        true,
			slotPace:                         time.Second,
			epochCleanupTime:                 60 * time.Second,
			wantErr:                          false,
			expectedNodekeys:                 []string{},
			expectedVotekeys:                 []string{},
			activeIdentity:                   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewExporterConfig(
				context.Background(),
				tt.httpTimeout,
				tt.rpcURL,
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

			require.NoError(t, err)

			// Verify config values
			assert.Equal(t, tt.httpTimeout, config.HTTPTimeout)
			assert.Equal(t, tt.rpcURL, config.RPCURL)
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

func TestValidateUniqueKeys(t *testing.T) {
	tests := []struct {
		name               string
		nodekeys, votekeys []string
		wantErr            bool
	}{
		{name: "no keys"},
		{name: "unique keys", nodekeys: []string{"aaa", "bbb"}, votekeys: []string{"AAA", "BBB"}},
		{name: "same key in both flags", nodekeys: []string{"aaa"}, votekeys: []string{"aaa"}},
		{name: "duplicate nodekey", nodekeys: []string{"aaa", "bbb", "aaa"}, wantErr: true},
		{name: "duplicate votekey", votekeys: []string{"AAA", "AAA"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ExporterConfig{Nodekeys: tt.nodekeys, Votekeys: tt.votekeys}
			err := config.validateUniqueKeys()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestValidateLightModeFlags(t *testing.T) {
	keys := []string{"aaa"}
	tests := []struct {
		name                             string
		nodekeys, votekeys, balanceAddrs []string
		comprehensiveSlotTracking        bool
		comprehensiveVoteAccountTracking bool
		monitorBlockSizes                bool
		wantErr                          bool
	}{
		{name: "no incompatible flags"},
		{name: "comprehensive slot tracking", comprehensiveSlotTracking: true, wantErr: true},
		{name: "comprehensive vote account tracking", comprehensiveVoteAccountTracking: true, wantErr: true},
		{name: "monitor block sizes", monitorBlockSizes: true, wantErr: true},
		{name: "nodekeys set", nodekeys: keys, wantErr: true},
		{name: "votekeys set", votekeys: keys, wantErr: true},
		{name: "balance addresses set", balanceAddrs: keys, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ExporterConfig{
				Nodekeys:                         tt.nodekeys,
				Votekeys:                         tt.votekeys,
				BalanceAddresses:                 tt.balanceAddrs,
				ComprehensiveSlotTracking:        tt.comprehensiveSlotTracking,
				ComprehensiveVoteAccountTracking: tt.comprehensiveVoteAccountTracking,
				MonitorBlockSizes:                tt.monitorBlockSizes,
				LightMode:                        true,
			}
			err := config.validateLightModeFlags()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}
