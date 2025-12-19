// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{
    tests::utils,
    transaction_filter::{TransactionFilter, TransactionMatcher},
};

#[test]
fn test_account_address_filter_simple() {
    for use_new_txn_payload_format in [false, true] {
        // Create a filter that only allows transactions from specific account addresses.
        // These are: (i) txn 0 sender; (ii) txn 1 sender; and (iii) txn 2 entry function address.
        let transactions = utils::create_entry_function_transactions(use_new_txn_payload_format);
        let filter = TransactionFilter::empty()
            .add_account_address_filter(true, transactions[0].sender())
            .add_account_address_filter(true, transactions[1].sender())
            .add_account_address_filter(true, utils::get_module_address(&transactions[2]))
            .add_all_filter(false);

        // Verify that the filter returns transactions from the specified account addresses
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[0..3].to_vec());

        // Create a filter that denies transactions from the specified account addresses (as above)
        let filter = TransactionFilter::empty()
            .add_account_address_filter(false, transactions[0].sender())
            .add_account_address_filter(false, transactions[1].sender())
            .add_account_address_filter(false, utils::get_module_address(&transactions[2]))
            .add_all_filter(true);

        // Verify that the filter returns transactions from other account addresses
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[3..].to_vec());
    }
}

#[test]
fn test_account_address_filter_multisig() {
    for use_new_txn_payload_format in [false, true] {
        // Create a filter that only allows transactions from specific account addresses.
        // These are: (i) txn 0 multisig address; (ii) txn 1 sender; and (iii) txn 2 multisig address.
        let transactions = utils::create_multisig_transactions(use_new_txn_payload_format);
        let filter = TransactionFilter::empty()
            .add_account_address_filter(true, utils::get_multisig_address(&transactions[0]))
            .add_account_address_filter(true, transactions[1].sender())
            .add_account_address_filter(true, utils::get_multisig_address(&transactions[2]))
            .add_all_filter(false);

        // Verify that the filter returns transactions from the specified account addresses
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[0..3].to_vec());

        // Create a filter that denies transactions from the specified account addresses (as above)
        let filter = TransactionFilter::empty()
            .add_account_address_filter(false, utils::get_multisig_address(&transactions[0]))
            .add_account_address_filter(false, transactions[1].sender())
            .add_account_address_filter(false, utils::get_multisig_address(&transactions[2]))
            .add_all_filter(true);

        // Verify that the filter returns transactions from other account addresses
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[3..].to_vec());
    }
}

#[test]
fn test_account_address_filter_script_argument() {
    for use_new_txn_payload_format in [false, true] {
        // Create a filter that only allows transactions from specific account addresses.
        // These are: (i) txn 0 script arg address; (ii) txn 1 sender; and (iii) txn 2 script arg address.
        let transactions = utils::create_script_transactions(use_new_txn_payload_format);
        let filter = TransactionFilter::empty()
            .add_account_address_filter(true, utils::get_script_argument_address(&transactions[0]))
            .add_account_address_filter(true, transactions[1].sender())
            .add_account_address_filter(true, utils::get_script_argument_address(&transactions[2]))
            .add_all_filter(false);

        // Verify that the filter returns transactions from the specified account addresses
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[0..3].to_vec());

        // Create a filter that denies transactions from the specified account addresses (as above)
        let filter = TransactionFilter::empty()
            .add_account_address_filter(false, utils::get_script_argument_address(&transactions[0]))
            .add_account_address_filter(false, transactions[1].sender())
            .add_account_address_filter(false, utils::get_script_argument_address(&transactions[2]))
            .add_all_filter(true);

        // Verify that the filter returns transactions from other account addresses
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[3..].to_vec());
    }
}

#[test]
fn test_account_address_filter_transaction_authenticator() {
    // Create a filter that only allows transactions from specific account addresses.
    // These are: (i) txn 0 account authenticator; (ii) txn 1 account authenticator; and (iii) txn 2 sender.
    let transactions = utils::create_fee_payer_transactions();
    let filter = TransactionFilter::empty()
        .add_account_address_filter(true, utils::get_fee_payer_address(&transactions[0]))
        .add_account_address_filter(true, utils::get_fee_payer_address(&transactions[1]))
        .add_account_address_filter(true, transactions[2].sender())
        .add_all_filter(false);

    // Verify that the filter returns transactions from the specified account addresses
    let filtered_transactions = filter.filter_transactions(transactions.clone());
    assert_eq!(filtered_transactions, transactions[0..3].to_vec());

    // Create a filter that denies transactions from the specified account addresses (as above)
    let filter = TransactionFilter::empty()
        .add_account_address_filter(false, utils::get_fee_payer_address(&transactions[0]))
        .add_account_address_filter(false, utils::get_fee_payer_address(&transactions[1]))
        .add_account_address_filter(false, transactions[2].sender())
        .add_all_filter(true);

    // Verify that the filter returns transactions from other account addresses
    let filtered_transactions = filter.filter_transactions(transactions.clone());
    assert_eq!(filtered_transactions, transactions[3..].to_vec());
}

#[test]
fn test_all_filter() {
    for use_new_txn_payload_format in [false, true] {
        // Create a filter that allows all transactions
        let filter = TransactionFilter::empty().add_all_filter(true);

        // Verify that all transactions are allowed
        let transactions = utils::create_entry_function_transactions(use_new_txn_payload_format);
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions);

        // Create a filter that denies all transactions
        let filter = TransactionFilter::empty().add_all_filter(false);

        // Verify that all transactions are denied
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert!(filtered_transactions.is_empty());
    }
}

#[test]
fn test_encrypted_transaction_filter() {
    // Create a filter that only allows encrypted transactions
    let transactions = utils::create_encrypted_and_plaintext_transactions();
    let filter = TransactionFilter::empty()
        .add_encrypted_transaction_filter(true)
        .add_all_filter(false);

    // Verify that the filter returns only encrypted transactions (txn 0, 1 and 2)
    let filtered_transactions = filter.filter_transactions(transactions.clone());
    assert_eq!(filtered_transactions, transactions[0..3].to_vec());

    // Create a filter that denies encrypted transactions
    let filter = TransactionFilter::empty()
        .add_encrypted_transaction_filter(false)
        .add_all_filter(true);

    // Verify that the filter returns only plaintext transactions (txn 3 onwards)
    let filtered_transactions = filter.filter_transactions(transactions.clone());
    assert_eq!(filtered_transactions, transactions[3..].to_vec());
}

#[test]
fn test_empty_filter() {
    for use_new_txn_payload_format in [false, true] {
        // Create an empty filter
        let filter = TransactionFilter::empty();

        // Verify that all transactions are allowed
        let transactions = utils::create_entry_function_transactions(use_new_txn_payload_format);
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions);
    }
}

#[test]
fn test_entry_function_filter() {
    for use_new_txn_payload_format in [false, true] {
        // Create a filter that only allows transactions with specific entry functions (txn 0 and txn 1)
        let transactions = utils::create_entry_function_transactions(use_new_txn_payload_format);
        let filter = TransactionFilter::empty()
            .add_entry_function_filter(
                true,
                utils::get_module_address(&transactions[0]),
                utils::get_module_name(&transactions[0]),
                utils::get_function_name(&transactions[0]),
            )
            .add_entry_function_filter(
                true,
                utils::get_module_address(&transactions[1]),
                utils::get_module_name(&transactions[1]),
                utils::get_function_name(&transactions[1]),
            )
            .add_all_filter(false);

        // Verify that the filter returns only transactions with the specified entry functions
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[0..2].to_vec());

        // Create a filter that denies transactions with specific entry functions (txn 0)
        let filter = TransactionFilter::empty()
            .add_entry_function_filter(
                false,
                utils::get_module_address(&transactions[0]),
                utils::get_module_name(&transactions[0]),
                utils::get_function_name(&transactions[0]),
            )
            .add_all_filter(true);

        // Verify that the filter returns all transactions except those with the specified entry functions
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[1..].to_vec());
    }
}

#[test]
fn test_module_address_filter() {
    for use_new_txn_payload_format in [false, true] {
        // Create a filter that only allows transactions from a specific module address (txn 0 and txn 1)
        let transactions = utils::create_entry_function_transactions(use_new_txn_payload_format);
        let filter = TransactionFilter::empty()
            .add_module_address_filter(true, utils::get_module_address(&transactions[0]))
            .add_module_address_filter(true, utils::get_module_address(&transactions[1]))
            .add_all_filter(false);

        // Verify that the filter returns only transactions from the specified module addresses
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[0..2].to_vec());

        // Create a filter that denies transactions from a specific module address (txn 0 and txn 1)
        let filter = TransactionFilter::empty()
            .add_module_address_filter(false, utils::get_module_address(&transactions[0]))
            .add_module_address_filter(false, utils::get_module_address(&transactions[1]))
            .add_all_filter(true);

        // Verify that the filter returns all transactions except those from the specified module addresses
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[2..].to_vec());
    }
}

#[test]
fn test_multiple_matchers_filter() {
    for use_new_txn_payload_format in [false, true] {
        // Create a filter that only allows transactions with specific criteria (only txn 1 should match)
        let transactions = utils::create_entry_function_transactions(use_new_txn_payload_format);
        let transaction_matchers = vec![
            TransactionMatcher::Sender(transactions[1].sender()),
            TransactionMatcher::ModuleAddress(utils::get_module_address(&transactions[1])),
            TransactionMatcher::EntryFunction(
                utils::get_module_address(&transactions[1]),
                utils::get_module_name(&transactions[1]),
                utils::get_function_name(&transactions[1]),
            ),
        ];
        let filter = TransactionFilter::empty()
            .add_multiple_matchers_filter(true, transaction_matchers.clone())
            .add_all_filter(false);

        // Verify that the filter returns only transactions that match all specified matchers
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, vec![transactions[1].clone()]);

        // Create a filter that only allows transactions with a specific criteria (none should match)
        let transaction_matchers = vec![
            TransactionMatcher::Sender(transactions[0].sender()),
            TransactionMatcher::ModuleAddress(utils::get_module_address(&transactions[1])),
            TransactionMatcher::ModuleAddress(utils::get_module_address(&transactions[2])),
        ];
        let filter = TransactionFilter::empty()
            .add_multiple_matchers_filter(true, transaction_matchers)
            .add_all_filter(false);

        // Verify that the filter returns no transactions (none should match)
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert!(filtered_transactions.is_empty());

        // Create a filter that denies transactions with a specific sender and module address (txn 0)
        let transaction_matchers = vec![
            TransactionMatcher::Sender(transactions[0].sender()),
            TransactionMatcher::ModuleAddress(utils::get_module_address(&transactions[0])),
        ];
        let filter = TransactionFilter::empty()
            .add_multiple_matchers_filter(false, transaction_matchers)
            .add_all_filter(true);

        // Verify that it returns all transactions except those with the specified sender and module address
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[1..].to_vec());
    }
}

#[test]
fn test_public_key_filter() {
    for use_new_txn_payload_format in [false, true] {
        // Create a filter that only allows transactions from specific public keys.
        // These are: (i) txn 0 authenticator public key; and (ii) txn 1 authenticator public key.
        let transactions = utils::create_entry_function_transactions(use_new_txn_payload_format);
        let filter = TransactionFilter::empty()
            .add_public_key_filter(true, utils::get_auth_public_key(&transactions[0]))
            .add_public_key_filter(true, utils::get_auth_public_key(&transactions[1]))
            .add_all_filter(false);

        // Verify that the filter returns transactions with the specified public keys
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[0..2].to_vec());

        // Create a filter that denies transactions from the specified public keys (as above)
        let filter = TransactionFilter::empty()
            .add_public_key_filter(false, utils::get_auth_public_key(&transactions[0]))
            .add_public_key_filter(false, utils::get_auth_public_key(&transactions[1]))
            .add_all_filter(true);

        // Verify that it returns transactions from other public keys
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[2..].to_vec());
    }
}

#[test]
fn test_sender_filter() {
    for use_new_txn_payload_format in [false, true] {
        // Create a filter that only allows transactions from a specific sender (txn 0 and txn 1)
        let transactions = utils::create_entry_function_transactions(use_new_txn_payload_format);
        let filter = TransactionFilter::empty()
            .add_sender_filter(true, transactions[0].sender())
            .add_sender_filter(true, transactions[1].sender())
            .add_all_filter(false);

        // Verify that the filter returns only transactions from the specified senders
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[0..2].to_vec());

        // Create a filter that denies transactions from a specific sender (txn 0 and txn 1)
        let filter = TransactionFilter::empty()
            .add_sender_filter(false, transactions[0].sender())
            .add_sender_filter(false, transactions[1].sender())
            .add_all_filter(true);

        // Verify that the filter returns all transactions except those from the specified senders
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[2..].to_vec());
    }
}

#[test]
fn test_transaction_id_filter() {
    for use_new_txn_payload_format in [false, true] {
        // Create a filter that only allows transactions with a specific transaction ID (txn 0)
        let transactions = utils::create_entry_function_transactions(use_new_txn_payload_format);
        let filter = TransactionFilter::empty()
            .add_transaction_id_filter(true, transactions[0].committed_hash())
            .add_all_filter(false);

        // Verify that the filter returns only the transaction with the specified ID
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, vec![transactions[0].clone()]);

        // Create a filter that denies transactions with a specific transaction ID (txn 0)
        let filter = TransactionFilter::empty()
            .add_transaction_id_filter(false, transactions[0].committed_hash())
            .add_all_filter(true);

        // Verify that the filter returns all transactions except the one with the specified ID
        let filtered_transactions = filter.filter_transactions(transactions.clone());
        assert_eq!(filtered_transactions, transactions[1..].to_vec());
    }
}

#[test]
fn test_only_aptos_account_transfer_filter() {
    for use_new_txn_payload_format in [false, true] {
        // Create a transaction that calls aptos_account::transfer (should be allowed)
        let aptos_account_transfer_txn = utils::create_entry_function_transaction(
            str::parse("0x1::aptos_account::transfer").unwrap(),
            use_new_txn_payload_format,
        );

        // Create transactions that call other functions (should be rejected)
        let other_txn_1 = utils::create_entry_function_transaction(
            str::parse("0x1::coin::transfer").unwrap(),
            use_new_txn_payload_format,
        );
        let other_txn_2 = utils::create_entry_function_transaction(
            str::parse("0x2::test_module::test_function").unwrap(),
            use_new_txn_payload_format,
        );
        let script_txn = utils::create_script_transaction(use_new_txn_payload_format);

        // Create the filter that only allows aptos_account::transfer
        let filter = TransactionFilter::only_aptos_account_transfer();

        // Verify that aptos_account::transfer transaction is allowed
        assert!(
            filter.allows_transaction(&aptos_account_transfer_txn),
            "aptos_account::transfer transaction should be allowed"
        );

        // Verify that other transactions are rejected
        assert!(
            !filter.allows_transaction(&other_txn_1),
            "coin::transfer transaction should be rejected"
        );
        assert!(
            !filter.allows_transaction(&other_txn_2),
            "Other entry function transaction should be rejected"
        );
        assert!(
            !filter.allows_transaction(&script_txn),
            "Script transaction should be rejected"
        );

        // Test filtering a batch of transactions
        let all_transactions = vec![
            aptos_account_transfer_txn.clone(),
            other_txn_1.clone(),
            other_txn_2.clone(),
            script_txn.clone(),
        ];

        let filtered_transactions = filter.filter_transactions(all_transactions.clone());
        assert_eq!(
            filtered_transactions.len(),
            1,
            "Only aptos_account::transfer should pass the filter"
        );
        assert_eq!(
            filtered_transactions[0], aptos_account_transfer_txn,
            "The filtered transaction should be aptos_account::transfer"
        );
    }
}
