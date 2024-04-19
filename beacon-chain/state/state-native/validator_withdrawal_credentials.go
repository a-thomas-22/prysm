package state_native

import (
	"bytes"

	"github.com/prysmaticlabs/prysm/v5/beacon-chain/state"
	"github.com/prysmaticlabs/prysm/v5/config/params"
)

// TODO: Move all of this to core/helpers.

// HasCompoundingWithdrawalCredentialUsingTrie checks if the validator has a compounding withdrawal credential.
// New in EIP-7251: https://eips.ethereum.org/EIPS/eip-7251
//
// Spec definition:
//
//	def has_compounding_withdrawal_credential(validator: Validator) -> bool:
//	    """
//	    Check if ``validator`` has an 0x02 prefixed "compounding" withdrawal credential.
//	    """
//	    return validator.withdrawal_credentials[:1] == COMPOUNDING_WITHDRAWAL_PREFIX
func HasCompoundingWithdrawalCredentialUsingTrie(v state.ReadOnlyValidator) bool {
	if v == nil {
		return false
	}
	return isCompoundingWithdrawalCredential(v.WithdrawalCredentials())
}

// isCompoundingWithdrawalCredential checks if the credentials are a compounding withdrawal credential.
//
// Spec definition:
//
//	def is_compounding_withdrawal_credential(withdrawal_credentials: Bytes32) -> bool:
//	    return withdrawal_credentials[:1] == COMPOUNDING_WITHDRAWAL_PREFIX
func isCompoundingWithdrawalCredential(creds []byte) bool {
	return bytes.HasPrefix(creds, []byte{params.BeaconConfig().CompoundingWithdrawalPrefix})
}
