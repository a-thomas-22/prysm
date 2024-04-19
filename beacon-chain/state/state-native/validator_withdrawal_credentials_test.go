package state_native_test

import (
	"testing"

	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/helpers"
	"github.com/prysmaticlabs/prysm/v5/config/params"
	"github.com/prysmaticlabs/prysm/v5/encoding/bytesutil"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
	"github.com/prysmaticlabs/prysm/v5/testing/assert"
)

// TODO: Test WithTrie version.
// TODO: Move this to helpers.
func TestHasExecutionWithdrawalCredentials(t *testing.T) {
	tests := []struct {
		name      string
		validator *ethpb.Validator
		want      bool
	}{
		{"Has compounding withdrawal credential",
			&ethpb.Validator{WithdrawalCredentials: bytesutil.PadTo([]byte{params.BeaconConfig().CompoundingWithdrawalPrefix}, 32)},
			true},
		{"Does not have compounding or execution withdrawal credential",
			&ethpb.Validator{WithdrawalCredentials: bytesutil.PadTo([]byte{0x00}, 32)},
			false},
		{"Has execution withdrawal credential",
			&ethpb.Validator{WithdrawalCredentials: bytesutil.PadTo([]byte{params.BeaconConfig().ETH1AddressWithdrawalPrefixByte}, 32)},
			true},
		{"Handles nil case", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, helpers.HasExecutionWithdrawalCredentials(tt.validator))
		})
	}
}
