package state_native

import (
	"github.com/prysmaticlabs/prysm/v5/config/features"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	ethpbv1 "github.com/prysmaticlabs/prysm/v5/proto/eth/v1"
)

func (b *BeaconState) AppendPendingBalanceDeposit(index primitives.ValidatorIndex, amount uint64) error {
	if features.Get().EnableExperimentalState {
		panic("not implemented")
	} else {
		b.lock.Lock()
		b.pendingBalanceDeposits = append(b.pendingBalanceDeposits, &ethpbv1.PendingBalanceDeposit{Index: uint64(index), Amount: amount})
		b.lock.Unlock()
	}

	//b.lock.Lock()
	//defer b.lock.Unlock()

	//b.valMapHandler.Set(bytesutil.ToBytes48(val.PublicKey), valIdx)
	//b.markFieldAsDirty(types.Validators)
	//b.addDirtyIndices(types.Validators, []uint64{uint64(valIdx)})
	return nil
}
