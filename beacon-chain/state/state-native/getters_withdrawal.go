package state_native

import (
	"github.com/pkg/errors"
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

// ExpectedWithdrawals returns the withdrawals that a proposer will need to pack in the next block
// applied to the current state. It is also used by validators to check that the execution payload carried
// the right number of withdrawals
//
// Spec definition:
//
//	def get_expected_withdrawals(state: BeaconState) -> Sequence[Withdrawal]:
//	    epoch = get_current_epoch(state)
//	    withdrawal_index = state.next_withdrawal_index
//	    validator_index = state.next_withdrawal_validator_index
//	    withdrawals: List[Withdrawal] = []
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
//	                amount=balance - MAX_EFFECTIVE_BALANCE,
//	            ))
//	            withdrawal_index += WithdrawalIndex(1)
//	        if len(withdrawals) == MAX_WITHDRAWALS_PER_PAYLOAD:
//	            break
//	        validator_index = ValidatorIndex((validator_index + 1) % len(state.validators))
//	    return withdrawals
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
		if balance > 0 && isFullyWithdrawableValidator(val, epoch) {
			withdrawals = append(withdrawals, &enginev1.Withdrawal{
				Index:          withdrawalIndex,
				ValidatorIndex: validatorIndex,
				Address:        bytesutil.SafeCopyBytes(val.WithdrawalCredentials[ETH1AddressOffset:]),
				Amount:         balance,
			})
			withdrawalIndex++
		} else if isPartiallyWithdrawableValidator(val, balance) {
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
	return withdrawals, nil
}

// hasETH1WithdrawalCredential returns whether the validator has an ETH1
// Withdrawal prefix. It assumes that the caller has a lock on the state
func hasETH1WithdrawalCredential(val *ethpb.Validator) bool {
	if val == nil {
		return false
	}
	cred := val.WithdrawalCredentials
	return len(cred) > 0 && cred[0] == params.BeaconConfig().ETH1AddressWithdrawalPrefixByte
}

// isFullyWithdrawableValidator returns whether the validator is able to perform a full
// withdrawal. This differ from the spec helper in that the balance > 0 is not
// checked. This function assumes that the caller holds a lock on the state.
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
func isFullyWithdrawableValidator(val *ethpb.Validator, epoch primitives.Epoch) bool {
	if val == nil {
		return false
	}

	return HasExecutionWithdrawalCredentials(val) &&
		val.WithdrawableEpoch <= epoch
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
//	    return (
//	        has_execution_withdrawal_credential(validator) # [Modified in EIP7251]
//	        and get_validator_excess_balance(validator, balance) > 0
//	    )
func isPartiallyWithdrawableValidator(val *ethpb.Validator, balance uint64) bool {
	// TODO: This method breaks spec tests
	if val == nil {
		return false
	}
	// TODO: HasExecutionWithdrawalCredentials is already checked in validator excess balance?
	// TODO: Add tests for this method that work with the old implementation, then add the new
	// implementation.
	return HasExecutionWithdrawalCredentials(val) && validatorExcessBalance(val, balance) > 0
}

// TODO: Delete after spec test issues are resolved.
func OLD_isPartiallyWithdrawableValidator(val *ethpb.Validator, balance uint64) bool {
	if val == nil {
		return false
	}
	hasMaxBalance := val.EffectiveBalance == params.BeaconConfig().MaxEffectiveBalance
	hasExcessBalance := balance > params.BeaconConfig().MaxEffectiveBalance
	return hasETH1WithdrawalCredential(val) && hasExcessBalance && hasMaxBalance
}

// validatorExcessBalance returns the gwei amount considered as "excess".
//
// Spec definition:
//
//	def get_validator_excess_balance(validator: Validator, balance: Gwei) -> Gwei:
//	    """
//	    Get excess balance for partial withdrawals for ``validator``.
//	    """
//	    if has_compounding_withdrawal_credential(validator) and balance > MAX_EFFECTIVE_BALANCE_EIP7251:
//	        return balance - MAX_EFFECTIVE_BALANCE_EIP7251
//	    elif has_eth1_withdrawal_credential(validator) and balance > MIN_ACTIVATION_BALANCE:
//	        return balance - MIN_ACTIVATION_BALANCE
//	    return Gwei(0)
func validatorExcessBalance(val *ethpb.Validator, balance uint64) uint64 {
	if HasCompoundingWithdrawalCredential(val) && balance > params.BeaconConfig().MaxEffectiveBalanceEIP7251 {
		return balance - params.BeaconConfig().MaxEffectiveBalanceEIP7251
	} else if hasETH1WithdrawalCredential(val) && balance > params.BeaconConfig().MinActivationBalance {
		return balance - params.BeaconConfig().MinActivationBalance
	}
	return 0
}
