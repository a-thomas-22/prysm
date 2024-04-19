package eip7251

import (
	"context"
	"slices"

	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/altair"
	e "github.com/prysmaticlabs/prysm/v5/beacon-chain/core/epoch"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/epoch/precompute"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/helpers"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/signing"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/state"
	"github.com/prysmaticlabs/prysm/v5/config/params"
	"github.com/prysmaticlabs/prysm/v5/crypto/bls"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
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

// ProcessConsolidations --
//
// Spec definition:
//
//	def process_consolidation(state: BeaconState, signed_consolidation: SignedConsolidation) -> None:
//	    # If the pending consolidations queue is full, no consolidations are allowed in the block
//	    assert len(state.pending_consolidations) < PENDING_CONSOLIDATIONS_LIMIT
//	    # If there is too little available consolidation churn limit, no consolidations are allowed in the block
//	    assert get_consolidation_churn_limit(state) > MIN_ACTIVATION_BALANCE
//	    consolidation = signed_consolidation.message
//	    # Verify that source != target, so a consolidation cannot be used as an exit.
//	    assert consolidation.source_index != consolidation.target_index
//
//	    source_validator = state.validators[consolidation.source_index]
//	    target_validator = state.validators[consolidation.target_index]
//	    # Verify the source and the target are active
//	    current_epoch = get_current_epoch(state)
//	    assert is_active_validator(source_validator, current_epoch)
//	    assert is_active_validator(target_validator, current_epoch)
//	    # Verify exits for source and target have not been initiated
//	    assert source_validator.exit_epoch == FAR_FUTURE_EPOCH
//	    assert target_validator.exit_epoch == FAR_FUTURE_EPOCH
//	    # Consolidations must specify an epoch when they become valid; they are not valid before then
//	    assert current_epoch >= consolidation.epoch
//
//	    # Verify the source and the target have Execution layer withdrawal credentials
//	    assert has_execution_withdrawal_credential(source_validator)
//	    assert has_execution_withdrawal_credential(target_validator)
//	    # Verify the same withdrawal address
//	    assert source_validator.withdrawal_credentials[12:] == target_validator.withdrawal_credentials[12:]
//
//	    # Verify consolidation is signed by the source and the target
//	    domain = compute_domain(DOMAIN_CONSOLIDATION, genesis_validators_root=state.genesis_validators_root)
//	    signing_root = compute_signing_root(consolidation, domain)
//	    pubkeys = [source_validator.pubkey, target_validator.pubkey]
//	    assert bls.FastAggregateVerify(pubkeys, signing_root, signed_consolidation.signature)
//
//	    # Initiate source validator exit and append pending consolidation
//	    source_validator.exit_epoch = compute_consolidation_epoch_and_update_churn(
//	        state, source_validator.effective_balance)
//	    source_validator.withdrawable_epoch = Epoch(
//	        source_validator.exit_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY
//	    )
//	    state.pending_consolidations.append(PendingConsolidation(
//	        source_index=consolidation.source_index,
//	        target_index=consolidation.target_index
//	    ))
func ProcessConsolidations(ctx context.Context, st state.BeaconState, cs []*ethpb.SignedConsolidation) (state.BeaconState, error) {
	_, span := trace.StartSpan(ctx, "eip7251.ProcessConsolidations")
	defer span.End()

	if st == nil || st.IsNil() {
		return nil, errors.New("nil state")
	}
	if cs == nil {
		return nil, errors.New("nil consolidations")
	}

	domain, err := signing.ComputeDomain(params.BeaconConfig().DomainConsolidation, st.Fork().CurrentVersion, st.GenesisValidatorsRoot())
	if err != nil {
		return nil, err
	}

	for _, c := range cs {
		if c == nil || c.Message == nil {
			return nil, errors.New("nil consolidation")
		}

		// TODO: can these be moved outside of the loop?
		if st.NumPendingConsolidations() >= params.BeaconConfig().PendingConsolidationsLimit {
			return nil, errors.New("pending consolidations queue is full")
		}

		totalBalance, err := helpers.TotalActiveBalance(st)
		if err != nil {
			return nil, err
		}
		if helpers.ConsolidationChurnLimit(totalBalance) <= params.BeaconConfig().MinActivationBalance {
			return nil, errors.New("too little available consolidation churn limit")
		}
		currentEpoch := slots.ToEpoch(st.Slot())
		// END TODO

		if c.Message.SourceIndex == c.Message.TargetIndex {
			return nil, errors.New("source and target index are the same")
		}
		source, err := st.ValidatorAtIndex(c.Message.SourceIndex)
		if err != nil {
			return nil, err
		}
		target, err := st.ValidatorAtIndex(c.Message.TargetIndex)
		if err != nil {
			return nil, err
		}
		if !helpers.IsActiveValidator(source, currentEpoch) {
			return nil, errors.New("source is not active")
		}
		if !helpers.IsActiveValidator(target, currentEpoch) {
			return nil, errors.New("target is not active")
		}
		if source.ExitEpoch != params.BeaconConfig().FarFutureEpoch {
			return nil, errors.New("source exit epoch has been initiated")
		}
		if target.ExitEpoch != params.BeaconConfig().FarFutureEpoch {
			return nil, errors.New("target exit epoch has been initiated")
		}
		if currentEpoch < c.Message.Epoch {
			return nil, errors.New("consolidation is not valid yet")
		}

		if !helpers.HasExecutionWithdrawalCredentials(source) {
			return nil, errors.New("source does not have execution withdrawal credentials")
		}
		if !helpers.HasExecutionWithdrawalCredentials(target) {
			return nil, errors.New("target does not have execution withdrawal credentials")
		}
		if !helpers.IsSameWithdrawalCredentials(source, target) {
			return nil, errors.New("source and target have different withdrawal credentials")
		}

		sr, err := signing.ComputeSigningRoot(c.Message, domain)
		if err != nil {
			return nil, err
		}
		sourcePk, err := bls.PublicKeyFromBytes(source.PublicKey)
		if err != nil {
			return nil, errors.Wrap(err, "could not convert bytes to public key")
		}
		targetPk, err := bls.PublicKeyFromBytes(target.PublicKey)
		if err != nil {
			return nil, errors.Wrap(err, "could not convert bytes to public key")
		}
		sig, err := bls.SignatureFromBytes(c.Signature)
		if err != nil {
			return nil, errors.Wrap(err, "could not convert bytes to signature")
		}
		if !sig.FastAggregateVerify([]bls.PublicKey{sourcePk, targetPk}, sr) {
			return nil, errors.New("consolidation signature verification failed")
		}

		sEE, err := ComputeConsolidationEpochAndUpdateChurn(ctx, st, source.EffectiveBalance)
		if err != nil {
			return nil, err
		}
		source.ExitEpoch = sEE
		source.WithdrawableEpoch = sEE + params.BeaconConfig().MinValidatorWithdrawabilityDelay
		if err := st.UpdateValidatorAtIndex(c.Message.SourceIndex, source); err != nil {
			return nil, err
		}
		if err := st.AppendPendingConsolidation(c.Message.ToPendingConsolidation()); err != nil {
			return nil, err
		}
	}

	return st, nil
}

func ProcessExecutionLayerWithdrawRequests(ctx context.Context, st state.BeaconState, wds []*ethpb.ExecutionLayerWithdrawalRequest) (state.BeaconState, error) {
	// TODO: Need to align with James He. This is a placeholder implementation.
	panic("implement me")
}
