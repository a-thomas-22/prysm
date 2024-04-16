package eip7251

import (
	"context"
	"slices"

	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/altair"
	e "github.com/prysmaticlabs/prysm/v5/beacon-chain/core/epoch"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/epoch/precompute"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/helpers"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/state"
	"github.com/prysmaticlabs/prysm/v5/time/slots"
	"go.opencensus.io/trace"
)

// ProcessEpoch describes the per epoch operations that are performed on the beacon state.
// It's optimized by pre computing validator attested info and epoch total/attested balances upfront.
//
// Spec definition:
//
//	def process_epoch(state: BeaconState) -> None:
//	    process_justification_and_finalization(state)
//	    process_inactivity_updates(state)
//	    process_rewards_and_penalties(state)
//	    process_registry_updates(state)
//	    process_slashings(state)
//	    process_eth1_data_reset(state)
//	    process_pending_balance_deposits(state)  # New in EIP7251
//	    process_pending_consolidations(state)  # New in EIP7251
//	    process_effective_balance_updates(state)
//	    process_slashings_reset(state)
//	    process_randao_mixes_reset(state)
func ProcessEpoch(ctx context.Context, state state.BeaconState) (state.BeaconState, error) {
	ctx, span := trace.StartSpan(ctx, "eip7251.ProcessEpoch")
	defer span.End()

	if state == nil || state.IsNil() {
		return nil, errors.New("nil state")
	}
	vp, bp, err := altair.InitializePrecomputeValidators(ctx, state)
	if err != nil {
		return nil, err
	}
	vp, bp, err = altair.ProcessEpochParticipation(ctx, state, bp, vp)
	if err != nil {
		return nil, err
	}
	state, err = precompute.ProcessJustificationAndFinalizationPreCompute(state, bp)
	if err != nil {
		return nil, errors.Wrap(err, "could not process justification")
	}
	state, vp, err = altair.ProcessInactivityScores(ctx, state, vp)
	if err != nil {
		return nil, errors.Wrap(err, "could not process inactivity updates")
	}
	state, err = altair.ProcessRewardsAndPenaltiesPrecompute(state, bp, vp)
	if err != nil {
		return nil, errors.Wrap(err, "could not process rewards and penalties")
	}
	state, err = e.ProcessRegistryUpdates(ctx, state)
	if err != nil {
		return nil, errors.Wrap(err, "could not process registry updates")
	}
	proportionalSlashingMultiplier, err := state.ProportionalSlashingMultiplier()
	if err != nil {
		return nil, err
	}
	state, err = e.ProcessSlashings(state, proportionalSlashingMultiplier)
	if err != nil {
		return nil, err
	}
	state, err = e.ProcessEth1DataReset(state)
	if err != nil {
		return nil, err
	}
	state, err = ProcessPendingBalanceDeposits(ctx, state, bp.ActiveCurrentEpoch)
	if err != nil {
		return nil, err
	}
	state, err = ProcessPendingConsolidations(ctx, state, bp.ActiveCurrentEpoch)
	if err != nil {
		return nil, err
	}
	state, err = e.ProcessEffectiveBalanceUpdates(state)
	if err != nil {
		return nil, err
	}
	state, err = e.ProcessSlashingsReset(state)
	if err != nil {
		return nil, err
	}
	state, err = e.ProcessRandaoMixesReset(state)
	if err != nil {
		return nil, err
	}
	state, err = e.ProcessHistoricalDataUpdate(state)
	if err != nil {
		return nil, err
	}

	state, err = altair.ProcessParticipationFlagUpdates(state)
	if err != nil {
		return nil, err
	}

	state, err = altair.ProcessSyncCommitteeUpdates(ctx, state)
	if err != nil {
		return nil, err
	}

	return state, nil
}

// ProcessPendingBalanceUpdates --
//
// Spec definition:
//
//	def process_pending_balance_deposits(state: BeaconState) -> None:
//	    available_for_processing = state.deposit_balance_to_consume + get_activation_exit_churn_limit(state)
//	    processed_amount = 0
//	    next_deposit_index = 0
//
//	    for deposit in state.pending_balance_deposits:
//	        if processed_amount + deposit.amount > available_for_processing:
//	            break
//	        increase_balance(state, deposit.index, deposit.amount)
//	        processed_amount += deposit.amount
//	        next_deposit_index += 1
//
//	    state.pending_balance_deposits = state.pending_balance_deposits[next_deposit_index:]
//
//	    if len(state.pending_balance_deposits) == 0:
//	        state.deposit_balance_to_consume = Gwei(0)
//	    else:
//	        state.deposit_balance_to_consume = available_for_processing - processed_amount
func ProcessPendingBalanceDeposits(ctx context.Context, st state.BeaconState, activeBalance uint64) (state.BeaconState, error) {
	_, span := trace.StartSpan(ctx, "eip7251.ProcessPendingBalanceDeposits")
	defer span.End()

	if st == nil || st.IsNil() {
		return nil, errors.New("nil state")
	}

	depBalToConsume, err := st.DepositBalanceToConsume()
	if err != nil {
		return nil, err
	}
	var activeBalGwei uint64 // TODO: get_active_balance(state)

	availableForProcessing := depBalToConsume + helpers.ActivationExitChurnLimit(activeBalGwei)
	processedAmount := uint64(0)
	nextDepositIndex := 0

	deposits, err := st.PendingBalanceDeposits()
	if err != nil {
		return nil, err
	}

	for _, deposit := range deposits {
		if processedAmount+deposit.Amount > availableForProcessing {
			break
		}
		if err := helpers.IncreaseBalance(st, deposit.Index, deposit.Amount); err != nil {
			return nil, err
		}
		processedAmount += deposit.Amount
		nextDepositIndex++
	}

	deposits = slices.Clip(deposits[nextDepositIndex:]) // TODO: Does clip make sense here or can it clip on copy?
	if err := st.SetPendingBalanceDeposits(deposits); err != nil {
		return nil, err
	}

	if len(deposits) == 0 {
		if err := st.SetDepositBalanceToConsume(0); err != nil {
			return nil, err
		}
	} else {
		if err := st.SetDepositBalanceToConsume(availableForProcessing - processedAmount); err != nil {
			return nil, err
		}
	}

	return st, nil
}

// ProcessPendingConsolidations --
//
// Spec definition:
//
//	def process_pending_consolidations(state: BeaconState) -> None:
//	    next_pending_consolidation = 0
//	    for pending_consolidation in state.pending_consolidations:
//	        source_validator = state.validators[pending_consolidation.source_index]
//	        if source_validator.slashed:
//	            next_pending_consolidation += 1
//	            continue
//	        if source_validator.withdrawable_epoch > get_current_epoch(state):
//	            break
//
//	        # Churn any target excess active balance of target and raise its max
//	        switch_to_compounding_validator(state, pending_consolidation.target_index)
//	        # Move active balance to target. Excess balance is withdrawable.
//	        active_balance = get_active_balance(state, pending_consolidation.source_index)
//	        decrease_balance(state, pending_consolidation.source_index, active_balance)
//	        increase_balance(state, pending_consolidation.target_index, active_balance)
//	        next_pending_consolidation += 1
//
//	    state.pending_consolidations = state.pending_consolidations[next_pending_consolidation:]
func ProcessPendingConsolidations(ctx context.Context, st state.BeaconState, activeBalance uint64) (state.BeaconState, error) {
	ctx, span := trace.StartSpan(ctx, "eip7251.ProcessPendingConsolidations")
	defer span.End()

	if st == nil || st.IsNil() {
		return nil, errors.New("nil state")
	}

	var nextPendingConsolidation uint64
	pendingConsolidations, err := st.PendingConsolidations()
	if err != nil {
		return nil, err
	}
	for _, pc := range pendingConsolidations {
		sourceValidator, err := st.ValidatorAtIndex(pc.SourceIndex)
		if err != nil {
			return nil, err
		}
		if sourceValidator.Slashed {
			nextPendingConsolidation++
			continue
		}
		if sourceValidator.WithdrawableEpoch > slots.ToEpoch(st.Slot()) {
			break
		}

		if err := SwitchToCompoundingValidator(ctx, st, pc.TargetIndex); err != nil {
			return nil, err
		}

		if err := helpers.DecreaseBalance(st, pc.SourceIndex, activeBalance); err != nil {
			return nil, err
		}
		if err := helpers.IncreaseBalance(st, pc.TargetIndex, activeBalance); err != nil {
			return nil, err
		}
		nextPendingConsolidation++
	}

	// TODO: Check OOB
	if err := st.SetPendingConsolidations(pendingConsolidations[nextPendingConsolidation:]); err != nil {
		return nil, err
	}

	return st, nil
}
