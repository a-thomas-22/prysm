package eip7251

import (
	"context"

	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/helpers"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/state"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	"github.com/prysmaticlabs/prysm/v5/time/slots"
)

// ComputeConsolidationEpochAndUpdateChurn
//
// Spec definition:
//
//	def compute_consolidation_epoch_and_update_churn(state: BeaconState, consolidation_balance: Gwei) -> Epoch:
//	    earliest_consolidation_epoch = compute_activation_exit_epoch(get_current_epoch(state))
//	    per_epoch_consolidation_churn = get_consolidation_churn_limit(state)
//	    # New epoch for consolidations.
//	    if state.earliest_consolidation_epoch < earliest_consolidation_epoch:
//	        state.earliest_consolidation_epoch = earliest_consolidation_epoch
//	        state.consolidation_balance_to_consume = per_epoch_consolidation_churn
//
//	    if consolidation_balance <= state.consolidation_balance_to_consume:
//	        # Consolidation fits in the current earliest consolidation epoch.
//	        state.consolidation_balance_to_consume -= consolidation_balance
//	    else:
//	        # Consolidation doesn't fit in the current earliest epoch.
//	        balance_to_process = consolidation_balance - state.consolidation_balance_to_consume
//	        additional_epochs, remainder = divmod(balance_to_process, per_epoch_consolidation_churn)
//	        state.earliest_consolidation_epoch += additional_epochs + 1
//	        state.consolidation_balance_to_consume = per_epoch_consolidation_churn - remainder
//
//	    return state.earliest_consolidation_epoch
func ComputeConsolidationEpochAndUpdateChurn(ctx context.Context, s state.BeaconState, consolidationBalance uint64) (primitives.Epoch, error) {
	earliestActivationEpoch := helpers.ActivationExitEpoch(slots.ToEpoch(s.Slot()))
	perEpochConsolidationChurn := helpers.ConsolidationChurnLimit(0 /*TODO*/)
	earliestEpoch, err := s.EarliestConsolidationEpoch()
	if err != nil {
		return 0, err
	}

	// New epoch for consolidations.
	if earliestEpoch < earliestActivationEpoch {
		if err := s.SetEarliestConsolidationEpoch(earliestActivationEpoch); err != nil {
			return 0, err
		}
		if err := s.SetConsolidationBalanceToConsume(perEpochConsolidationChurn); err != nil {
			return 0, err
		}
	}
	b, err := s.ConsolidationBalanceToConsume()
	if err != nil {
		return 0, err
	}
	if consolidationBalance <= b {
		if err := s.SetConsolidationBalanceToConsume(b - consolidationBalance); err != nil {
			return 0, err
		}
	} else {
		balToProcess := consolidationBalance - b
		additionalEpochs, remainder := balToProcess/perEpochConsolidationChurn, balToProcess%perEpochConsolidationChurn
		if err := s.SetEarliestConsolidationEpoch(earliestEpoch + primitives.Epoch(additionalEpochs+1)); err != nil {
			return 0, err
		}
		if err := s.SetConsolidationBalanceToConsume(perEpochConsolidationChurn - remainder); err != nil {
			return 0, err
		}
	}

	return s.EarliestConsolidationEpoch()
}
