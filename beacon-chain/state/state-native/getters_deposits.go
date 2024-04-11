package state_native

import (
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
)

func (b *BeaconState) pendingBalanceDepositsVal() []*ethpb.PendingBalanceDeposit {
	if b.pendingBalanceDeposits == nil {
		return nil
	}

	return ethpb.CopyPendingBalanceDeposits(b.pendingBalanceDeposits)
}
