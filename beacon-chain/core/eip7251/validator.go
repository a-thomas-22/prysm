package eip7251

import (
	"context"

	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/helpers"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/state"
	"github.com/prysmaticlabs/prysm/v5/config/params"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
)

// SwitchToCompoundingValidator
//
// Spec definition:
//
//	 def switch_to_compounding_validator(state: BeaconState, index: ValidatorIndex) -> None:
//
//		validator = state.validators[index]
//		if has_eth1_withdrawal_credential(validator):
//		    validator.withdrawal_credentials[:1] = COMPOUNDING_WITHDRAWAL_PREFIX
//		    queue_excess_active_balance(state, index)
func SwitchToCompoundingValidator(ctx context.Context, s state.BeaconState, idx primitives.ValidatorIndex) error {
	v, err := s.ValidatorAtIndex(idx)
	if err != nil {
		return err
	}
	if helpers.HasETH1WithdrawalCredential(v) {
		v.WithdrawalCredentials[0] = params.BeaconConfig().CompoundingWithdrawalPrefix
		return queueExcessActiveBalance(ctx, s, idx)
	}
	return nil
}

// queueExcessActiveBalance
//
// Spec definition:
//
//	def queue_excess_active_balance(state: BeaconState, index: ValidatorIndex) -> None:
//	    balance = state.balances[index]
//	    if balance > MIN_ACTIVATION_BALANCE:
//	        excess_balance = balance - MIN_ACTIVATION_BALANCE
//	        state.balances[index] = MIN_ACTIVATION_BALANCE
//	        state.pending_balance_deposits.append(
//	            PendingBalanceDeposit(index=index, amount=excess_balance)
//	        )
func queueExcessActiveBalance(ctx context.Context, s state.BeaconState, idx primitives.ValidatorIndex) error {
	bal, err := s.BalanceAtIndex(idx)
	if err != nil {
		return err
	}

	if bal > params.BeaconConfig().MinActivationBalance {
		excessBalance := bal - params.BeaconConfig().MinActivationBalance
		if err := s.UpdateBalancesAtIndex(idx, params.BeaconConfig().MinActivationBalance); err != nil {
			return err
		}
		return s.AppendPendingBalanceDeposit(idx, excessBalance)
	}
	return nil
}
