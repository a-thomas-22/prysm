package state_native

import (
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
)

func (b *BeaconState) pendingConsolidationsVal() []*ethpb.PendingConsolidation {
	if b.pendingConsolidations == nil {
		return nil
	}

	return ethpb.CopyPendingConsolidations(b.pendingConsolidations)
}
