// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**********************************************************************************************************************/

program credits.aleo;

/**********************************************************************************************************************/

/// The `committee` mapping contains the active validator set and their corresponding stake.
mapping committee:
    // The key represents the address of the validator.
    key as address.public;
    // The value represents the committee state of the validator.
    value as committee_state.public;

// The `committee_state` struct tracks the total stake of the validator, and whether they are open to stakers.
struct committee_state:
    // The amount of microcredits bonded to the validator, by the validator and its delegators.
    microcredits as u64;
    // The boolean flag indicating if the validator is open to stakers.
    is_open as boolean;
    // The delegate address of the validator pledged.
    delegate_address as address;
/**********************************************************************************************************************/

// The `bonded` mapping represents the amount of microcredits that are currently bonded.
mapping bonded:
    // The key represents the address of the staker, which includes the validators and their delegators.
    key as address.public;
    // The value represents the bond state.
    value as bond_state.public;

// The `bond_state` struct tracks the amount of microcredits that are currently bonded to the specified validator.
struct bond_state:
    // The address of the validator.
    validator as address;
    // The amount of microcredits that are currently bonded to the specified validator.
    microcredits as u64;

/**********************************************************************************************************************/

// The `unbonding` mapping contains a set of stakers with their unbonding microcredits and unlock height.
mapping unbonding:
    // The key represents the address of the staker, which includes the validators and their delegators.
    key as address.public;
    // The value represents the unbond state.
    value as unbond_state.public;

// The `unbond_state` struct tracks the microcredits that are currently unbonding, along with the unlock height.
struct unbond_state:
    // The amount of microcredits that are currently unbonding.
    microcredits as u64;
    // The block height at which the unbonding will be complete, and can be claimed.
    height as u32;

/**********************************************************************************************************************/

// The `account` mapping is used to store credits publicly.
mapping account:
    // The key represents the address of the owner.
    key as address.public;
    // The value represents the amount of public microcredits that belong to the specified owner.
    value as u64.public;

/**********************************************************************************************************************/

// The `credits` record is used to store credits privately.
record credits:
    // The address of the owner.
    owner as address.private;
    // The amount of private microcredits that belong to the specified owner.
    microcredits as u64.private;

/**********************************************************************************************************************/

// This function allows any staker to bond their microcredits to a validator.
// The corresponding functions for 'bond_public' are 'unbond_public' and 'claim_unbond_public'.
function bond_public:
    // Input the validator's address.
    input r0 as address.public;
    // Input the amount of microcredits to bond.
    input r1 as u64.public;

    // Determine if the amount is at least one credit.
    gte r1 1_000_000u64 into r2;
    // Enforce the amount is at least one credit.
    assert.eq r2 true;

    // Bond the specified amount of microcredits to the specified validator.
    async bond_public self.caller r0 r1 into r3;
    // Output the finalize future.
    output r3 as credits.aleo/bond_public.future;

finalize bond_public:
    // Input the staker's address.
    input r0 as address.public;
    // Input the validator's address.
    input r1 as address.public;
    // Input the amount of microcredits to bond.
    input r2 as u64.public;

    // Determine whether the caller is a validator.
    is.eq r0 r1 into r3;
    // If the caller is a validator, jump to the `bond_validator` logic.
    branch.eq r3 true to bond_validator;
    // If the caller is not a validator, jump to the `bond_delegator` logic.
    branch.eq r3 false to bond_delegator;

    /******* Bond Validator *******/

    // Starts the `bond_validator` logic.
    position bond_validator;

    /* Committee */

    // Construct the initial committee state.
    // Note: We set the initial 'is_open' state to 'true' 'delegate_address' to caller.
    cast 0u64 true r0 into r4 as committee_state;
    // Retrieve the committee state of the specified validator.
    get.or_use committee[r0] r4 into r5;
    // Ensure that the validator is open to stakers.
    assert.eq r5.is_open true;

    // Increment the stake for the specified validator.
    add r5.microcredits r2 into r6;
    // Construct the updated committee state.
    cast r6 r5.is_open r5.delegate_address into r7 as committee_state;

    /* Bonded */

    // Construct the initial bond state.
    cast r1 0u64 into r8 as bond_state;
    // Get the bond state for the caller, or default to the initial bond state.
    get.or_use bonded[r0] r8 into r9;
    // Enforce the validator matches in the bond state.
    assert.eq r9.validator r1;

    // Increment the microcredits in the bond state.
    add r9.microcredits r2 into r10;
    // Determine if the amount is at least one million credits.
    gte r10 1_000_000_000_000u64 into r11;
    // Enforce the amount is at least one million credits.
    assert.eq r11 true;

    // Construct the updated bond state.
    cast r1 r10 into r12 as bond_state;

    /* Account */

    // Get the balance of the caller.
    // If the account does not exist, this finalize scope will fail.
    get account[r0] into r13;
    // Decrement the balance of the caller.
    sub r13 r2 into r14;

    /* Writes */

    // Update the committee state of the specified validator.
    set r7 into committee[r0];
    // Update the bond state for the caller.
    set r12 into bonded[r0];
    // Update the balance of the caller.
    set r14 into account[r0];

    // Ends the `bond_validator` logic.
    branch.eq true true to end;

    /******* Bond Delegator *******/

    // Starts the `bond_delegator` logic.
    position bond_delegator;

    /* Committee */

    // Check if the caller is a validator.
    contains committee[r0] into r15;
    // Enforce the caller is *not* a validator.
    assert.eq r15 false;

    // Check if the address specified in the stake is a validator.
    contains committee[r1] into r16;
    // If the address specified in the stake is a validator, jump to the `bond_exist_delegator` logic.
    branch.eq r16 true to bond_exist_delegator;
    // If the address specified in the stake is not a validator, jump to the `bond_new_delegator` logic.
    branch.eq r16 false to bond_new_delegator;

    /******* Bond Exist Delegator *******/

    position bond_exist_delegator;
    // Get the stake for the specified validator.
    get committee[r1] into r17;
    // Ensure that the validator is open to stakers.
    assert.eq r17.is_open true;

    // Increment the stake for the specified validator.
    add r17.microcredits r2 into r18;
    // Construct the updated committee state.
    cast r18 r17.is_open r17.delegate_address into r19 as committee_state;

    /* Bonded */

    // Construct the initial bond state.
    cast r1 0u64 into r20 as bond_state;
    // Get the bond state for the caller, or default to the initial bond state.
    get.or_use bonded[r0] r20 into r21;
    // Enforce the validator matches in the bond state.
    assert.eq r21.validator r1;

    // Increment the microcredits in the bond state.
    add r21.microcredits r2 into r22;
    // Determine if the amount is at least 10 credits.
    gte r22 10_000_000u64 into r23;
    // Enforce the amount is at least 10 credits.
    assert.eq r23 true;

    // Construct the updated bond state.
    cast r1 r22 into r24 as bond_state;

    /* Account */

    // Get the balance of the caller.
    // If the account does not exist, this finalize scope will fail.
    get account[r0] into r25;
    // Decrement the balance of the caller.
    sub r25 r2 into r26;

    /* Writes */

    // Update the committee state for the specified validator.
    set r19 into committee[r1];
    // Update the bond state for the caller.
    set r24 into bonded[r0];
    // Update the balance of the caller.
    set r26 into account[r0];
    // Ends the `bond_exist_delegator` logic.
    branch.eq true true to end;

    /******* Bond New Delegator *******/

    position bond_new_delegator;

    /* Committee */

    // Construct the initial committee state.
    // Note: We set the initial 'is_open' state to 'true'.
    cast 0u64 true r0 into r27 as committee_state;
    // Retrieve the committee state of the specified validator.
    get.or_use committee[r1] r27 into r28;
    // Ensure that the validator is open to stakers.
    assert.eq r28.is_open true;

    // Increment the stake for the specified validator.
    add r28.microcredits r2 into r29;
    // Construct the updated committee state.
    cast r29 r28.is_open r28.delegate_address into r30 as committee_state;

    /* Bonded */

    // Check if the stake for the specified address never bond.
    contains bonded[r1] into r31;
    // Enforce the stake for the specified address never bond.
    assert.eq r31 false;
    // Construct the initial bond state.
    cast r1 0u64 into r32 as bond_state;
    // Get the bond state for the staker, or default to the initial bond state.
    get.or_use bonded[r0] r32 into r33;
    // Enforce the validator matches in the bond state.
    assert.eq r33.validator r1;

    // Increment the microcredits in the bond state.
    add r33.microcredits r2 into r34;
    // Determine if the amount is at least one million credits.
    gte r34 1_000_000_000_000u64 into r35;
    // Enforce the amount is at least one million credits.
    assert.eq r35 true;

    // Construct the updated bond state.
    cast r1 r34 into r36 as bond_state;

    /* Account */

    // Get the balance of the caller.
    // If the account does not exist, this finalize scope will fail.
    get account[r0] into r37;
    // Decrement the balance of the caller.
    sub r37 r2 into r38;

    /* Writes */

    // Update the committee state of the specified validator.
    set r30 into committee[r1];
    // Update the bond state for the caller.
    set r36 into bonded[r0];
    // Update the balance of the caller.
    set r38 into account[r0];
    // The terminus.
    position end;

/**********************************************************************************************************************/

// This function allows any staker to unbond their microcredits from a validator.
// The corresponding functions for 'unbond_public' is 'claim_unbond_public'.
function unbond_public:
    // Input the amount of microcredits to unbond.
    input r0 as u64.public;

    // Unbond the specified amount of microcredits to the caller.
    async unbond_public self.caller r0 into r1;
    // Output the finalize future.
    output r1 as credits.aleo/unbond_public.future;

finalize unbond_public:
    // Input the staker's address.
    input r0 as address.public;
    // Input the amount of microcredits to unbond.
    input r1 as u64.public;

    // Construct the initial unbond state.
    cast 0u64 0u32 into r2 as unbond_state;
    // Get the unbond state for the caller, or default to the initial unbond state.
    get.or_use unbonding[r0] r2 into r3;

    // Compute the height at which the unbonding will be complete, starting from the current block.
    // Note: Calling unbond across multiple blocks before the unbonding is complete will reset the height each time.
    add block.height 360u32 into r4;

    // Determine if the caller is a validator or delegator.
    contains committee[r0] into r5;

    // If the caller is a validator, jump to the `unbond_validator` logic.
    branch.eq r5 true to unbond_validator;
    // If the caller is not a validator, jump to the `unbond_delegator` logic.
    branch.eq r5 false to unbond_delegator;

    /******* Unbond Validator *******/

    // Starts the `unbond_validator` logic.
    position unbond_validator;

    /* Committee */

    // Get the committee state for the specified validator.
    get committee[r0] into r6;
    // Decrement the stake for the specified validator.
    sub r6.microcredits r1 into r7;
    // Ensure that the validator not a delegate validator.
    assert.eq r6.delegate_address r0;

    /* Bonded */

    // Get the bond state for the validator, or fail if it does not exist.
    get bonded[r0] into r8;
    // Ensure that the validator matches in the bond state.
    assert.eq r8.validator r0;
    // Decrement the microcredits in the bond state.
    sub r8.microcredits r1 into r9;

    // Determine if the remaining bond is at least one million credits.
    gte r9 1_000_000_000_000u64 into r10;

    // If the remaining balance is at least 1 million credits, jump to the `decrement_validator` logic.
    branch.eq r10 true to decrement_validator;
    // If the remaining balance is less than 1 million credits, jump to the `remove_validator` logic.
    branch.eq r10 false to remove_validator;

    /*** Decrement Validator ***/

    // Starts the `decrement_validator` logic.
    position decrement_validator;

    /* Committee */

    // Construct the updated committee state.
    cast r7 r6.is_open r6.delegate_address into r11 as committee_state;
    // Update the committee state for the validator.
    set r11 into committee[r0];

    /* Bonded */

    // Construct the updated bond state.
    cast r0 r9 into r12 as bond_state;
    // Update the bond state for the validator.
    set r12 into bonded[r0];

    /* Unbonding */

    // Increment the microcredits in the unbond state.
    add r3.microcredits r1 into r13;

    // Construct the updated unbond state.
    cast r13 r4 into r14 as unbond_state;
    // Update the unbond state for the caller.
    set r14 into unbonding[r0];

    // Ends the `decrement_validator` logic.
    branch.eq true true to end;

    /*** Remove Validator ***/

    // Starts the `remove_validator` logic.
    position remove_validator;

    // Ensure that the validator has no delegators.
    assert.eq r6.microcredits r8.microcredits;

    /* Committee */

    // Remove the validator from the committee.
    remove committee[r0];

    /* Bonded */

    // Remove the bond state for the validator.
    remove bonded[r0];

    /* Unbonding */

    // Increment the microcredits in the unbond state.
    add r3.microcredits r8.microcredits into r15;

    // Construct the updated unbond state.
    cast r15 r4 into r16 as unbond_state;
    // Update the unbond state for the caller.
    set r16 into unbonding[r0];

    // Ends the `remove_validator` logic.
    branch.eq true true to end;

    /******* Unbond Delegator *******/

    // Starts the `unbond_delegator` logic.
    position unbond_delegator;

    // Get the bond state for the caller, or fail if it does not exist.
    get bonded[r0] into r17;

    // Get the committee state for the specified validator.
    get committee[r17.validator] into r18;

    // Get the bond state for the delegate_address, or fail if it does not exist.
    get bonded[r18.delegate_address] into r19;

    // Decrement the microcredits in the bond state.
    sub r19.microcredits r1 into r20;

    // Determine if the remaining bond is at least one million credits.
    gte r20 1_000_000_000_000u64 into r21;

    // If the remaining balance is at least 1 million credits, jump to the `process_delegator` logic.
    branch.eq r21 true to process_delegator;
    // If the remaining balance is at least 1 million credits, jump to the `remove_delegator_committee` logic.
    branch.eq r21 false to remove_delegator_committee;

    /******* Remove Delegator Committee *******/

    // Starts the `remove_delegator_committee` logic.
    position remove_delegator_committee;

    // Ensure that the validator has no delegators.
    assert.eq r18.microcredits r19.microcredits;

    // Remove the validator from the committee.
    remove committee[r17.validator];

    // Remove the bond state for the validator.
    remove bonded[r0];

    // Increment the microcredits in the unbond state.
    add r3.microcredits r17.microcredits into r22;

    // Construct the updated unbond state.
    cast r22 r4 into r23 as unbond_state;

    // Update the unbond state for the caller.
    set r23 into unbonding[r0];
    // Ends the `remove_delegator_committee` logic.
    branch.eq true true to end;

    /******* Process Delegator *******/

    position process_delegator;
    // Decrement the microcredits in the bond state.
    sub r17.microcredits r1 into r24;

    // Determine if the remaining bond is at least 10 credits.
    gte r24 10_000_000u64 into r25;

    // If the remaining balance is at least 10 credits, jump to the `decrement_delegator` logic.
    branch.eq r25 true to decrement_delegator;
    // If the remaining balance is less than 10 credits, jump to the `remove_delegator` logic.
    branch.eq r25 false to remove_delegator;

    /*** Decrement Delegator ***/

    // Starts the `decrement_delegator` logic.
    position decrement_delegator;

    /* Committee */

    // Get the stake for the specified validator.
    // If the validator does not exist, this finalize scope will fail.
    get committee[r17.validator] into r26;
    // Decrement the stake for the specified validator.
    sub r26.microcredits r1 into r27;
    // Construct the updated committee state.
    cast r27 r26.is_open r26.delegate_address into r28 as committee_state;
    // Update the stake for the specified validator.
    set r28 into committee[r17.validator];

    /* Bonded */

    // Construct the updated bond state.
    cast r17.validator r24 into r29 as bond_state;
    // Update the bond state for the caller.
    set r29 into bonded[r0];

    /* Unbonding */

    // Increment the microcredits in the unbond state.
    add r3.microcredits r1 into r30;

    // Construct the updated unbond state.
    cast r30 r4 into r31 as unbond_state;
    // Update the unbond state for the caller.
    set r31 into unbonding[r0];

    // Ends the `decrement_delegator` logic.
    branch.eq true true to end;

    /*** Remove Delegator ***/

    // Starts the `remove_delegator` logic.
    position remove_delegator;

    /* Committee */

    // Get the stake for the specified validator.
    // If the validator does not exist, this finalize scope will fail.
    get committee[r17.validator] into r32;
    // Decrement the stake for the specified validator.
    sub r32.microcredits r17.microcredits into r33;
    // Construct the updated committee state.
    cast r33 r32.is_open r32.delegate_address into r34 as committee_state;
    // Update the stake for the specified validator.
    set r34 into committee[r17.validator];

    /* Bonded */

    // Remove the caller from the bonded mapping.
    remove bonded[r0];

    /* Unbonding */

    // Increment the microcredits in the unbond state.
    add r3.microcredits r17.microcredits into r35;

    // Construct the updated unbond state.
    cast r35 r4 into r36 as unbond_state;
    // Update the unbond state for the caller.
    set r36 into unbonding[r0];

    // The terminus.
    position end;

/**********************************************************************************************************************/

// This function allows a validator to unbond any delegator that is bonded to them.
function unbond_delegator_as_validator:
    // Input the delegator's address.
    input r0 as address.public;

    // Unbond the delegator as the validator.
    async unbond_delegator_as_validator self.caller r0 into r1;
    // Output the finalize future.
    output r1 as credits.aleo/unbond_delegator_as_validator.future;

finalize unbond_delegator_as_validator:
    // Input the validator's address.
    input r0 as address.public;
    // Input the delegator's address.
    input r1 as address.public;

    /* Start Committee */

    // Get the committee state for the specified validator.
    // If the validator does not exist, this finalize scope will fail.
    get committee[r0] into r2;
    // Enforce that the validator is closed to stakers.
    assert.eq r2.is_open false;
    // Enforce not a first delegate_address(owner address)
    assert.neq r2.delegate_address r1;
    // Enforce not validator's address.
    assert.neq r0 r1;

    // Check if the delegator is a validator.
    contains committee[r1] into r3;
    // Enforce the delegator is *not* a validator.
    assert.eq r3 false;

    /* End Committee */

    /* Start Bonded */

    // Get the bond state for the delegator, or fail if it does not exist.
    get bonded[r1] into r4;
    // Enforce that the delegator is bonded to the validator.
    assert.eq r4.validator r0;

    /* End Bonded */

    /* Start Committee */

    // Decrement the stake for the specified validator.
    sub r2.microcredits r4.microcredits into r5;
    // Construct the updated committee state.
    cast r5 r2.is_open r2.delegate_address into r6 as committee_state;

    /* End Committee */

    /* Start Unbond */

    // Construct the initial unbond state.
    cast 0u64 0u32 into r7 as unbond_state;
    // Get the unbond state for the delegator, or default to the initial unbond state.
    get.or_use unbonding[r1] r7 into r8;

    // Increment the microcredits in the unbond state.
    add r8.microcredits r4.microcredits into r9;
    // Compute the height at which the unbonding will be complete, starting from the current block.
    // Note: Calling unbond across multiple blocks before the unbonding is complete will reset the height each time.
    add block.height 360u32 into r10;

    // Construct the updated unbond state.
    cast r9 r10 into r11 as unbond_state;

    /* End Unbond */

    /* Start Writes */

    // Update the committee state for the specified validator.
    set r6 into committee[r0];
    // Remove the bond state for the delegator.
    remove bonded[r1];
    // Update the unbond state for the delegator.
    set r11 into unbonding[r1];

    /* End Writes */

/**********************************************************************************************************************/

// This function allows any staker to claim their microcredits after the unbonding period.
function claim_unbond_public:
    // Claim the unbonded microcredits.
    async claim_unbond_public self.caller into r0;
    // Output the finalize future.
    output r0 as credits.aleo/claim_unbond_public.future;

finalize claim_unbond_public:
    // Input the staker's address.
    input r0 as address.public;

    // Get the unbond state for the caller, or fail if it does not exist.
    get unbonding[r0] into r1;
    // Determine if unbonding is complete.
    gte block.height r1.height into r2;
    // Enforce the unbonding is complete.
    assert.eq r2 true;

    // Add the unbonded amount to the stakers's public balance.
    // Increments `account[r0]` by `r1`.
    // If `account[r0]` does not exist, 0u64 is used.
    // If `account[r0] + r2` overflows, `claim_unbond_public` is reverted.
    get.or_use account[r0] 0u64 into r3;
    add r1.microcredits r3 into r4;
    set r4 into account[r0];

    // Remove the unbond state for the caller.
    remove unbonding[r0];

/**********************************************************************************************************************/

// This function allows a validator to set their state to be either opened or closed to stakers.
// When the validator is open to stakers, any staker (including the validator) can bond or unbond from the validator.
// When the validator is closed to stakers, all stakers can only unbond from the validator.
//
// This function serves two primary purposes:
// 1. Allow a validator to leave the committee, by closing themselves to stakers and then unbonding all of their stakers.
// 2. Allow a validator to maintain their % of stake, by closing themselves to allowing more stakers to bond to them.
function set_validator_state:
    // Input the 'is_open' state.
    input r0 as boolean.public;
    // Set the validator to be either open or closed to stakers.
    async set_validator_state self.caller r0 into r1;
    // Output the finalize future.
    output r1 as credits.aleo/set_validator_state.future;

finalize set_validator_state:
    // Input the validator's address.
    input r0 as address.public;
    // Input the 'is_open' state.
    input r1 as boolean.public;

    // Get the committee state for the specified validator.
    // If the validator does not exist, this finalize scope will fail.
    get committee[r0] into r2;

    // Construct the updated committee state.
    cast r2.microcredits r1 r2.delegate_address into r3 as committee_state;
    // Update the committee state for the specified validator.
    set r3 into committee[r0];

/**********************************************************************************************************************/

// The `transfer_public` function sends the specified amount
// from the sender's `account` to the receiver's `account`.
function transfer_public:
    // Input the receiver.
    input r0 as address.public;
    // Input the amount.
    input r1 as u64.public;
    // Transfer the credits publicly.
    async transfer_public self.caller r0 r1 into r2;
    // Output the finalize future.
    output r2 as credits.aleo/transfer_public.future;

finalize transfer_public:
    // Input the sender.
    input r0 as address.public;
    // Input the receiver.
    input r1 as address.public;
    // Input the amount.
    input r2 as u64.public;
    // Decrements `account[r0]` by `r2`.
    // If `account[r0] - r2` underflows, `transfer_public` is reverted.
    get account[r0] into r3;
    sub r3 r2 into r4;
    set r4 into account[r0];
    // Increments `account[r1]` by `r2`.
    // If `account[r1]` does not exist, 0u64 is used.
    // If `account[r1] + r2` overflows, `transfer_public` is reverted.
    get.or_use account[r1] 0u64 into r5;
    add r5 r2 into r6;
    set r6 into account[r1];

/**********************************************************************************************************************/

// The `transfer_private` function sends the specified amount
// from the sender's record to the receiver in a record.
function transfer_private:
    // Input the sender's record.
    input r0 as credits.record;
    // Input the receiver.
    input r1 as address.private;
    // Input the amount.
    input r2 as u64.private;
    // Checks the given record has a sufficient amount.
    // This `sub` operation is safe, and the proof will fail
    // if an underflow occurs. The destination register `r3` holds
    // the change amount to be returned to the sender.
    sub r0.microcredits r2 into r3;
    // Construct a record for the specified receiver.
    cast r1 r2 into r4 as credits.record;
    // Construct a record with the change amount for the sender.
    cast r0.owner r3 into r5 as credits.record;
    // Output the receiver's record.
    output r4 as credits.record;
    // Output the sender's change record.
    output r5 as credits.record;

/**********************************************************************************************************************/

// The `transfer_private_to_public` function turns a specified amount
// from a record into public credits for the specified receiver.
//
// This function preserves privacy for the sender's record, however
// it publicly reveals the receiver and the amount.
function transfer_private_to_public:
    // Input the sender's record.
    input r0 as credits.record;
    // Input the receiver.
    input r1 as address.public;
    // Input the amount.
    input r2 as u64.public;
    // Checks the given record has a sufficient amount.
    // This `sub` operation is safe, and the proof will fail
    // if an underflow occurs. The destination register `r3` holds
    // the change amount for the sender.
    sub r0.microcredits r2 into r3;
    // Construct a record with the change amount for the sender.
    cast r0.owner r3 into r4 as credits.record;
    // Increment the amount publicly for the receiver.
    async transfer_private_to_public r1 r2 into r5;
    // Output the sender's change record.
    output r4 as credits.record;
    // Output the finalize future.
    output r5 as credits.aleo/transfer_private_to_public.future;

finalize transfer_private_to_public:
    // Input the receiver.
    input r0 as address.public;
    // Input the amount.
    input r1 as u64.public;
    // Retrieve the balance of the receiver.
    // If `account[r0]` does not exist, 0u64 is used.
    get.or_use account[r0] 0u64 into r2;
    // Increments `account[r0]` by `r1`.
    // If `r1 + r2` overflows, `transfer_private_to_public` is reverted.
    add r1 r2 into r3;
    // Updates the balance of the sender.
    set r3 into account[r0];

/**********************************************************************************************************************/

// The `transfer_public_to_private` function turns a specified amount
// from the mapping `account` into a record for the specified receiver.
//
// This function publicly reveals the sender, the receiver, and the specified amount.
// However, subsequent methods using the receiver's record can preserve the receiver's privacy.
function transfer_public_to_private:
    // Input the receiver.
    input r0 as address.private;
    // Input the amount.
    input r1 as u64.public;
    // Construct a record for the receiver.
    cast r0 r1 into r2 as credits.record;
    // Decrement the balance of the sender publicly.
    async transfer_public_to_private self.caller r1 into r3;
    // Output the record of the receiver.
    output r2 as credits.record;
    // Output the finalize future.
    output r3 as credits.aleo/transfer_public_to_private.future;

finalize transfer_public_to_private:
    // Input the sender.
    input r0 as address.public;
    // Input the amount.
    input r1 as u64.public;
    // Retrieve the balance of the sender.
    get account[r0] into r2;
    // Decrements `account[r0]` by `r1`.
    // If `r2 - r1` underflows, `transfer_public_to_private` is reverted.
    sub r2 r1 into r3;
    // Updates the balance of the sender.
    set r3 into account[r0];

/**********************************************************************************************************************/

// The `join` function combines two records into one.
function join:
    // Input the first record.
    input r0 as credits.record;
    // Input the second record.
    input r1 as credits.record;
    // Combines the amount of the first record and the second record.
    // This `add` operation is safe, and the proof will fail
    // if an overflow occurs.
    add r0.microcredits r1.microcredits into r2;
    // Construct a record with the combined amount.
    cast r0.owner r2 into r3 as credits.record;
    // Output the record.
    output r3 as credits.record;

/**********************************************************************************************************************/

// The `split` function splits a record into two records. The given input amount will be stored in the first record,
// and the remaining amount will be stored in the second record, with the fee deducted from the remaining amount.
// If the caller executes a transaction that contains only a call to this function, then the transaction does not
// require a fee, unless the caller wishes to provide an additional fee. Transactions that contain multiple transitions
// (that include one or more calls to this function) will require a fee as per standard consensus rules.
function split:
    // Input the record.
    input r0 as credits.record;
    // Input the amount to split.
    input r1 as u64.private;
    // Checks the given record has a sufficient amount to split.
    // This `sub` operation is safe, and the proof will fail
    // if an underflow occurs.
    sub r0.microcredits r1 into r2;
    // Checks the given record has a sufficient fee to remove.
    // This `sub` operation is safe, and the proof will fail
    // if an underflow occurs.
    sub r2 10_000u64 into r3;
    // Construct the first record.
    cast r0.owner r1 into r4 as credits.record;
    // Construct the second record.
    cast r0.owner r3 into r5 as credits.record;
    // Output the first record.
    output r4 as credits.record;
    // Output the second record.
    output r5 as credits.record;

/**********************************************************************************************************************/

// The `fee_private` function charges the specified amount from the sender's record.
function fee_private:
    // Input the sender's record.
    input r0 as credits.record;
    // Input the amount.
    input r1 as u64.public;
    // Input the priority fee amount.
    input r2 as u64.public;
    // Input the deployment or execution ID.
    input r3 as field.public;
    // Ensure the amount is nonzero.
    assert.neq r1 0u64;
    // Ensure the deployment or execution ID is nonzero.
    assert.neq r3 0field;
    // Add the fee and priority fee amounts.
    add r1 r2 into r4;
    // Checks the given record has a sufficient amount.
    // This `sub` operation is safe, and the proof will fail
    // if an underflow occurs. The destination register `r3` holds
    // the change amount for the sender.
    sub r0.microcredits r4 into r5;
    // Construct a record with the change amount for the sender.
    cast r0.owner r5 into r6 as credits.record;
    // Output the sender's change record.
    output r6 as credits.record;

/**********************************************************************************************************************/

// The `fee_public` function charges the specified amount from the sender's account.
function fee_public:
    // Input the amount.
    input r0 as u64.public;
    // Input the priority fee amount.
    input r1 as u64.public;
    // Input the deployment or execution ID.
    input r2 as field.public;
    // Ensure the amount is nonzero.
    assert.neq r0 0u64;
    // Ensure the deployment or execution ID is nonzero.
    assert.neq r2 0field;
    // Add the fee and priority fee amounts.
    add r0 r1 into r3;
    // Decrement the balance of the sender publicly.
    async fee_public self.caller r3 into r4;
    // Output the finalize future.
    output r4 as credits.aleo/fee_public.future;

finalize fee_public:
    // Input the sender's address.
    input r0 as address.public;
    // Input the total fee amount.
    input r1 as u64.public;
    // Retrieve the balance of the sender.
    // If `account[r0]` does not exist, `fee_public` is reverted.
    get account[r0] into r2;
    // Decrements `account[r0]` by `r1`.
    // If `r2 - r1` underflows, `fee_public` is reverted.
    sub r2 r1 into r3;
    // Updates the balance of the sender.
    set r3 into account[r0];

/**********************************************************************************************************************/

// Open Questions:
// fn bond
// - if the bond is now 33% or more, close the validator. (determine how hard to impl this)

/**********************************************************************************************************************/
