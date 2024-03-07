package helpers_test

import (
	"testing"

	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/helpers"
	"github.com/prysmaticlabs/prysm/v5/config/params"
	"github.com/prysmaticlabs/prysm/v5/testing/assert"
)

func TestChurnLimit(t *testing.T) {
	tests := []struct {
		name          string
		activeBalance uint64
		expected      uint64
	}{
		{
			name:          "less than MIN_PER_EPOCH_CHURN_LIMIT_EIP7251",
			activeBalance: 111,
			expected:      params.BeaconConfig().MinPerEpochChurnLimitEIP7251,
		},
		{
			name:          "modulo EFFECTIVE_BALANCE_INCREMENT",
			activeBalance: 111 + params.BeaconConfig().MinPerEpochChurnLimitEIP7251*params.BeaconConfig().ChurnLimitQuotient,
			expected:      params.BeaconConfig().MinPerEpochChurnLimitEIP7251,
		},
		{
			name:          "more than MIN_PER_EPOCH_CHURN_LIMIT_EIP7251",
			activeBalance: 2000 * params.BeaconConfig().EffectiveBalanceIncrement * params.BeaconConfig().ChurnLimitQuotient,
			expected:      2000 * params.BeaconConfig().EffectiveBalanceIncrement,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, helpers.ChurnLimit(tt.activeBalance))
		})
	}
}
