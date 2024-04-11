package state_native

import (
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/state/state-native/types"
)

var eip7251Fields = append(
	denebFields,
	types.DepositBalanceToConsume,
	types.ExitBalanceToConsume,
	types.EarliestExitEpoch,
	types.ConsolidationBalanceToConsume,
	types.EarliestConsolidationEpoch,
	types.PendingBalanceDeposits,
	types.PendingPartialWithdrawals,
	types.PendingConsolidations,
)

const (
	eip7251SharedFieldRefCount                  = 20 // TODO: Confirm 20
	experimentalStateEIP7251SharedFieldCountRef = 12 // TODO: Confirm 12
)
