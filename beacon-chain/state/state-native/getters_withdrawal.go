package state_native

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/helpers"
	"github.com/prysmaticlabs/prysm/v5/config/params"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	"github.com/prysmaticlabs/prysm/v5/encoding/bytesutil"
	mathutil "github.com/prysmaticlabs/prysm/v5/math"
	enginev1 "github.com/prysmaticlabs/prysm/v5/proto/engine/v1"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
	"github.com/prysmaticlabs/prysm/v5/runtime/version"
	"github.com/prysmaticlabs/prysm/v5/time/slots"
)

const ETH1AddressOffset = 12

// NextWithdrawalIndex returns the index that will be assigned to the next withdrawal.
func (b *BeaconState) NextWithdrawalIndex() (uint64, error) {
	if b.version < version.Capella {
		return 0, errNotSupported("NextWithdrawalIndex", b.version)
	}

	b.lock.RLock()
	defer b.lock.RUnlock()

	return b.nextWithdrawalIndex, nil
}

// NextWithdrawalValidatorIndex returns the index of the validator which is
// next in line for a withdrawal.
func (b *BeaconState) NextWithdrawalValidatorIndex() (primitives.ValidatorIndex, error) {
	if b.version < version.Capella {
		return 0, errNotSupported("NextWithdrawalValidatorIndex", b.version)
	}

	b.lock.RLock()
	defer b.lock.RUnlock()

	return b.nextWithdrawalValidatorIndex, nil
}

// TODO: Is this supposed to be here?

// ExpectedWithdrawals returns the withdrawals that a proposer will need to pack in the next block
// applied to the current state. It is also used by validators to check that the execution payload carried
// the right number of withdrawals
//
// Spec definition:
//
//	def get_expected_withdrawals(state: BeaconState) -> Tuple[Sequence[Withdrawal], uint64]:
//	    epoch = get_current_epoch(state)
//	    withdrawal_index = state.next_withdrawal_index
//	    validator_index = state.next_withdrawal_validator_index
//	    withdrawals: List[Withdrawal] = []
//
//	    # [New in EIP7251] Consume pending partial withdrawals
//	    for withdrawal in state.pending_partial_withdrawals:
//	        if withdrawal.withdrawable_epoch > epoch or len(withdrawals) == MAX_PARTIAL_WITHDRAWALS_PER_PAYLOAD:
//	            break
//
//	        validator = state.validators[withdrawal.index]
//	        if validator.exit_epoch == FAR_FUTURE_EPOCH and state.balances[withdrawal.index] > MIN_ACTIVATION_BALANCE:
//	            withdrawable_balance = min(state.balances[withdrawal.index] - MIN_ACTIVATION_BALANCE, withdrawal.amount)
//	            withdrawals.append(Withdrawal(
//	                index=withdrawal_index,
//	                validator_index=withdrawal.index,
//	                address=ExecutionAddress(validator.withdrawal_credentials[12:]),
//	                amount=withdrawable_balance,
//	            ))
//	            withdrawal_index += WithdrawalIndex(1)
//
//	    partial_withdrawals_count = len(withdrawals)
//	    # END: Consume pending partial withdrawals
//
//	    # Sweep for remaining.
//	    bound = min(len(state.validators), MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)
//	    for _ in range(bound):
//	        validator = state.validators[validator_index]
//	        balance = state.balances[validator_index]
//	        if is_fully_withdrawable_validator(validator, balance, epoch):
//	            withdrawals.append(Withdrawal(
//	                index=withdrawal_index,
//	                validator_index=validator_index,
//	                address=ExecutionAddress(validator.withdrawal_credentials[12:]),
//	                amount=balance,
//	            ))
//	            withdrawal_index += WithdrawalIndex(1)
//	        elif is_partially_withdrawable_validator(validator, balance):
//	            withdrawals.append(Withdrawal(
//	                index=withdrawal_index,
//	                validator_index=validator_index,
//	                address=ExecutionAddress(validator.withdrawal_credentials[12:]),
//	                amount=get_validator_excess_balance(validator, balance),  # [Modified in EIP7251]
//	            ))
//	            withdrawal_index += WithdrawalIndex(1)
//	        if len(withdrawals) == MAX_WITHDRAWALS_PER_PAYLOAD:
//	            break
//	        validator_index = ValidatorIndex((validator_index + 1) % len(state.validators))
//	    return withdrawals, partial_withdrawals_count
func (b *BeaconState) ExpectedWithdrawals() ([]*enginev1.Withdrawal, error) {
	if b.version < version.Capella {
		return nil, errNotSupported("ExpectedWithdrawals", b.version)
	}

	b.lock.RLock()
	defer b.lock.RUnlock()

	withdrawals := make([]*enginev1.Withdrawal, 0, params.BeaconConfig().MaxWithdrawalsPerPayload)
	validatorIndex := b.nextWithdrawalValidatorIndex
	withdrawalIndex := b.nextWithdrawalIndex
	epoch := slots.ToEpoch(b.slot)

	// EIP-7251 partial withdrawals functionality.
	if epoch >= params.BeaconConfig().EIP7251ForkEpoch {
		for _, w := range b.pendingPartialWithdrawals {
			if primitives.Epoch(w.WithdrawableEpoch) > epoch || len(withdrawals) >= int(params.BeaconConfig().MaxPartialWithdrawalsPerPayload) {
				break
			}

			v, err := b.validatorAtIndex(primitives.ValidatorIndex(w.Index))
			if err != nil {
				return nil, fmt.Errorf("failed to determine withdrawals: %w", err)
			}
			// TODO: Confirm safe index access.
			if v.ExitEpoch == params.BeaconConfig().FarFutureEpoch && b.balances[w.Index] > params.BeaconConfig().MinActivationBalance {
				amount := min(b.balances[w.Index]-params.BeaconConfig().MinActivationBalance, w.Amount)
				withdrawals = append(withdrawals, &enginev1.Withdrawal{
					Index:          withdrawalIndex,
					ValidatorIndex: primitives.ValidatorIndex(w.Index),
					Address:        v.WithdrawalCredentials[12:],
					Amount:         amount,
				})
				withdrawalIndex++
			}
		}
	}
	partialWithdrawalsCount := uint64(len(withdrawals))

	validatorsLen := b.validatorsLen()
	bound := mathutil.Min(uint64(validatorsLen), params.BeaconConfig().MaxValidatorsPerWithdrawalsSweep)
	for i := uint64(0); i < bound; i++ {
		val, err := b.validatorAtIndex(validatorIndex)
		if err != nil {
			return nil, errors.Wrapf(err, "could not retrieve validator at index %d", validatorIndex)
		}
		balance, err := b.balanceAtIndex(validatorIndex)
		if err != nil {
			return nil, errors.Wrapf(err, "could not retrieve balance at index %d", validatorIndex)
		}
		if isFullyWithdrawableValidator(val, balance, epoch) {
			withdrawals = append(withdrawals, &enginev1.Withdrawal{
				Index:          withdrawalIndex,
				ValidatorIndex: validatorIndex,
				Address:        bytesutil.SafeCopyBytes(val.WithdrawalCredentials[ETH1AddressOffset:]),
				Amount:         balance,
			})
			withdrawalIndex++
		} else if isPartiallyWithdrawableValidator(val, balance, epoch) {
			withdrawals = append(withdrawals, &enginev1.Withdrawal{
				Index:          withdrawalIndex,
				ValidatorIndex: validatorIndex,
				Address:        bytesutil.SafeCopyBytes(val.WithdrawalCredentials[ETH1AddressOffset:]),
				Amount:         balance - params.BeaconConfig().MaxEffectiveBalance,
			})
			withdrawalIndex++
		}
		if uint64(len(withdrawals)) == params.BeaconConfig().MaxWithdrawalsPerPayload {
			break
		}
		validatorIndex += 1
		if uint64(validatorIndex) == uint64(validatorsLen) {
			validatorIndex = 0
		}
	}

	_ = partialWithdrawalsCount // TODO: Return as second arg
	return withdrawals, nil
}

// isFullyWithdrawableValidator returns whether the validator is able to perform a full
// withdrawal. This function assumes that the caller holds a lock on the state.
//
// Spec definition:
//
//	def is_fully_withdrawable_validator(validator: Validator, balance: Gwei, epoch: Epoch) -> bool:
//	    """
//	    Check if ``validator`` is fully withdrawable.
//	    """
//	    return (
//	        has_execution_withdrawal_credential(validator)  # [Modified in EIP7251]
//	        and validator.withdrawable_epoch <= epoch
//	        and balance > 0
//	    )
func isFullyWithdrawableValidator(val *ethpb.Validator, balance uint64, epoch primitives.Epoch) bool {
	if val == nil || balance <= 0 {
		return false
	}

	// EIP-7251 logic
	if epoch >= params.BeaconConfig().EIP7251ForkEpoch {
		return HasExecutionWithdrawalCredentials(val) && val.WithdrawableEpoch <= epoch
	}

	return helpers.HasETH1WithdrawalCredential(val) && val.WithdrawableEpoch <= epoch
}

// isPartiallyWithdrawable returns whether the validator is able to perform a
// partial withdrawal. This function assumes that the caller has a lock on the state.
//
// Spec definition:
//
//	def is_partially_withdrawable_validator(validator: Validator, balance: Gwei) -> bool:
//	    """
//	    Check if ``validator`` is partially withdrawable.
//	    """
//	    max_effective_balance = get_validator_max_effective_balance(validator)
//	    has_max_effective_balance = validator.effective_balance == max_effective_balance  # [Modified in EIP7251]
//	    has_excess_balance = balance > max_effective_balance  # [Modified in EIP7251]
//	    return (
//	        has_execution_withdrawal_credential(validator)  # [Modified in EIP7251]
//	        and has_max_effective_balance
//	        and has_excess_balance
//	    )
func isPartiallyWithdrawableValidator(val *ethpb.Validator, balance uint64, epoch primitives.Epoch) bool {
	if val == nil {
		return false
	}

	if epoch >= params.BeaconConfig().EIP7251ForkEpoch {
		maxEB := validatorMaxEffectiveBalance(val)
		hasMaxBalance := val.EffectiveBalance == maxEB
		hasExcessBalance := balance > maxEB

		return HasExecutionWithdrawalCredentials(val) &&
			hasMaxBalance &&
			hasExcessBalance
	}

	hasMaxBalance := val.EffectiveBalance == params.BeaconConfig().MaxEffectiveBalance
	hasExcessBalance := balance > params.BeaconConfig().MaxEffectiveBalance
	return helpers.HasETH1WithdrawalCredential(val) && hasExcessBalance && hasMaxBalance
}

// validatorMaxEffectiveBalance returns the maximum effective balance for a validator.
//
// Spec definition:
//
//	def get_validator_max_effective_balance(validator: Validator) -> Gwei:
//	    """
//	    Get max effective balance for ``validator``.
//	    """
//	    if has_compounding_withdrawal_credential(validator):
//	        return MAX_EFFECTIVE_BALANCE_EIP7251
//	    else:
//	        return MIN_ACTIVATION_BALANCE
func validatorMaxEffectiveBalance(val *ethpb.Validator) uint64 {
	if HasCompoundingWithdrawalCredential(val) {
		return params.BeaconConfig().MaxEffectiveBalanceEIP7251
	}
	return params.BeaconConfig().MinActivationBalance
}

func (b *BeaconState) pendingPartialWithdrawalsVal() []*ethpb.PartialWithdrawal {
	return ethpb.CopyPendingPartialWithdrawals(b.pendingPartialWithdrawals)
}

// TODO: This goes in exits file?
// ExitEpochAndUpdateChurn
//
// Spec definition:
//
//	def compute_exit_epoch_and_update_churn(state: BeaconState, exit_balance: Gwei) -> Epoch:
//	    earliest_exit_epoch = compute_activation_exit_epoch(get_current_epoch(state))
//	    per_epoch_churn = get_activation_exit_churn_limit(state)
//	    # New epoch for exits.
//	    if state.earliest_exit_epoch < earliest_exit_epoch:
//	        state.earliest_exit_epoch = earliest_exit_epoch
//	        state.exit_balance_to_consume = per_epoch_churn
//
//	    if exit_balance <= state.exit_balance_to_consume:
//	        # Exit fits in the current earliest epoch.
//	        state.exit_balance_to_consume -= exit_balance
//	    else:
//	        # Exit doesn't fit in the current earliest epoch.
//	        balance_to_process = exit_balance - state.exit_balance_to_consume
//	        additional_epochs, remainder = divmod(balance_to_process, per_epoch_churn)
//	        state.earliest_exit_epoch += additional_epochs + 1
//	        state.exit_balance_to_consume = per_epoch_churn - remainder
//
// return state.earliest_exit_epoch
func (b *BeaconState) ExitEpochAndUpdateChurn(exitBalance uint64) (primitives.Epoch, error) {
	if b.version < version.EIP7251 {
		return 0, errNotSupported("ExitEpochAndUpdateChurn", b.version)
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	earliestExitEpoch := helpers.ActivationExitEpoch(slots.ToEpoch(b.slot))
	activeBal, err := helpers.TotalActiveBalance(b)
	if err != nil {
		return 0, err
	}
	// Guaranteed to be non-zero.
	perEpochChurn := helpers.ActivationExitChurnLimit(helpers.ActivationExitChurnLimit(activeBal))

	// New epoch for exits
	if b.earliestExitEpoch < earliestExitEpoch {
		b.earliestExitEpoch = earliestExitEpoch
		b.exitBalanceToConsume = perEpochChurn
	}

	if exitBalance <= b.exitBalanceToConsume {
		b.exitBalanceToConsume -= exitBalance
	} else {
		// exit doesn't fit in the current earliest epoch
		balanceToProcess := exitBalance - b.exitBalanceToConsume
		additionalEpochs, remainder := balanceToProcess/perEpochChurn, balanceToProcess%perEpochChurn
		b.earliestExitEpoch += primitives.Epoch(additionalEpochs + 1)
		b.exitBalanceToConsume = perEpochChurn - remainder
	}

	return b.earliestExitEpoch, nil
}
