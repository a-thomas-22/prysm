package state_native

import (
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
	"github.com/prysmaticlabs/prysm/v5/runtime/version"
)

func (b *BeaconState) EarliestConsolidationEpoch() (primitives.Epoch, error) {
	if b.version < version.EIP7251 {
		return 0, errNotSupported("EarliestConsolidationEpoch", b.version)
	}
	b.lock.RLock() // TODO: Is this necessary?
	defer b.lock.RUnlock()
	return b.earliestConsolidationEpoch, nil
}

func (b *BeaconState) ConsolidationBalanceToConsume() (uint64, error) {
	if b.version < version.EIP7251 {
		return 0, errNotSupported("ConsolidationBalanceToConsume", b.version)
	}
	b.lock.RLock() // TODO: Is this necessary?
	defer b.lock.RUnlock()
	return b.consolidationBalanceToConsume, nil
}

func (b *BeaconState) SetEarliestConsolidationEpoch(epoch primitives.Epoch) error {
	if b.version < version.EIP7251 {
		return errNotSupported("SetEarliestConsolidationEpoch", b.version)
	}
	b.lock.Lock() // TODO: Is this necessary?
	defer b.lock.Unlock()

	b.earliestConsolidationEpoch = epoch
	return nil
}

func (b *BeaconState) SetConsolidationBalanceToConsume(balance uint64) error {
	if b.version < version.EIP7251 {
		return errNotSupported("SetConsolidationBalanceToConsume", b.version)
	}
	b.lock.Lock() // TODO: Is this necessary?
	defer b.lock.Unlock()

	b.consolidationBalanceToConsume = balance
	return nil
}

func (b *BeaconState) DepositBalanceToConsume() (uint64, error) {
	if b.version < version.EIP7251 {
		return 0, errNotSupported("DepositBalanceToConsume", b.version)
	}
	b.lock.RLock() // TODO: Is this necessary?
	defer b.lock.RUnlock()
	return b.depositBalanceToConsume, nil
}

func (b *BeaconState) PendingBalanceDeposits() ([]*ethpb.PendingBalanceDeposit, error) {
	if b.version < version.EIP7251 {
		return nil, errNotSupported("PendingBalanceDeposits", b.version)
	}
	b.lock.RLock() // TODO: Is this necessary?
	defer b.lock.RUnlock()
	return b.pendingBalanceDeposits, nil
}

func (b *BeaconState) PendingConsolidations() ([]*ethpb.PendingConsolidation, error) {
	if b.version < version.EIP7251 {
		return nil, errNotSupported("PendingConsolidations", b.version)
	}
	b.lock.RLock() // TODO: Is this necessary?
	defer b.lock.RUnlock()
	return b.pendingConsolidations, nil
}

func (b *BeaconState) SetDepositBalanceToConsume(gwei uint64) error {
	if b.version < version.EIP7251 {
		return errNotSupported("SetDepositBalanceToConsume", b.version)
	}
	b.lock.Lock() // TODO: Is this necessary?
	defer b.lock.Unlock()

	b.depositBalanceToConsume = gwei
	return nil
}

func (b *BeaconState) SetPendingBalanceDeposits(val []*ethpb.PendingBalanceDeposit) error {
	if b.version < version.EIP7251 {
		return errNotSupported("SetPendingBalanceDeposits", b.version)
	}
	b.lock.Lock() // TODO: Is this necessary?
	defer b.lock.Unlock()

	b.pendingBalanceDeposits = val
	return nil
}

func (b *BeaconState) SetPendingConsolidations(val []*ethpb.PendingConsolidation) error {
	if b.version < version.EIP7251 {
		return errNotSupported("SetPendingConsolidations", b.version)
	}
	b.lock.Lock() // TODO: Is this necessary?
	defer b.lock.Unlock()

	b.pendingConsolidations = val
	return nil
}
