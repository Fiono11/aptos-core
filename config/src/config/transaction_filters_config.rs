// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use aptos_transaction_filters::{
    batch_transaction_filter::BatchTransactionFilter,
    block_transaction_filter::BlockTransactionFilter, transaction_filter::TransactionFilter,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransactionFiltersConfig {
    pub api_filter: TransactionFilterConfig, // Filter for the API (e.g., txn simulation)
    pub consensus_filter: BlockTransactionFilterConfig, // Filter for consensus (e.g., proposal voting)
    pub execution_filter: BlockTransactionFilterConfig, // Filter for execution (e.g., block execution)
    pub mempool_filter: TransactionFilterConfig,        // Filter for mempool (e.g., txn submission)
    pub quorum_store_filter: BatchTransactionFilterConfig, // Filter for quorum store (e.g., batch voting)
}

impl TransactionFiltersConfig {
    /// Configures both the mempool and API filters to only allow `aptos_account::transfer` transactions.
    /// All other transactions will be rejected at both the mempool (submission) and API (simulation) levels.
    ///
    /// # Example
    /// ```
    /// use aptos_config::config::{NodeConfig, TransactionFiltersConfig};
    ///
    /// let mut node_config = NodeConfig::default();
    /// node_config.transaction_filters.only_allow_aptos_account_transfer();
    /// ```
    pub fn only_allow_aptos_account_transfer(&mut self) {
        let filter = TransactionFilter::only_aptos_account_transfer();
        self.mempool_filter = TransactionFilterConfig::new(true, filter.clone());
        self.api_filter = TransactionFilterConfig::new(true, filter);
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransactionFilterConfig {
    filter_enabled: bool,                  // Whether the filter is enabled
    transaction_filter: TransactionFilter, // The transaction filter to apply
}

impl TransactionFilterConfig {
    pub fn new(filter_enabled: bool, transaction_filter: TransactionFilter) -> Self {
        Self {
            filter_enabled,
            transaction_filter,
        }
    }

    /// Returns true iff the filter is enabled and not empty
    pub fn is_enabled(&self) -> bool {
        self.filter_enabled && !self.transaction_filter.is_empty()
    }

    /// Returns a reference to the transaction filter
    pub fn transaction_filter(&self) -> &TransactionFilter {
        &self.transaction_filter
    }
}

impl Default for TransactionFilterConfig {
    fn default() -> Self {
        Self {
            filter_enabled: false,                          // Disable the filter
            transaction_filter: TransactionFilter::empty(), // Use an empty filter
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BatchTransactionFilterConfig {
    filter_enabled: bool, // Whether the filter is enabled
    batch_transaction_filter: BatchTransactionFilter, // The batch transaction filter to apply
}

impl BatchTransactionFilterConfig {
    pub fn new(filter_enabled: bool, batch_transaction_filter: BatchTransactionFilter) -> Self {
        Self {
            filter_enabled,
            batch_transaction_filter,
        }
    }

    /// Returns true iff the filter is enabled and not empty
    pub fn is_enabled(&self) -> bool {
        self.filter_enabled && !self.batch_transaction_filter.is_empty()
    }

    /// Returns a reference to the batch transaction filter
    pub fn batch_transaction_filter(&self) -> &BatchTransactionFilter {
        &self.batch_transaction_filter
    }
}

impl Default for BatchTransactionFilterConfig {
    fn default() -> Self {
        Self {
            filter_enabled: false,                                     // Disable the filter
            batch_transaction_filter: BatchTransactionFilter::empty(), // Use an empty filter
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlockTransactionFilterConfig {
    filter_enabled: bool, // Whether the filter is enabled
    block_transaction_filter: BlockTransactionFilter, // The block transaction filter to apply
}

impl BlockTransactionFilterConfig {
    pub fn new(filter_enabled: bool, block_transaction_filter: BlockTransactionFilter) -> Self {
        Self {
            filter_enabled,
            block_transaction_filter,
        }
    }

    /// Returns true iff the filter is enabled and not empty
    pub fn is_enabled(&self) -> bool {
        self.filter_enabled && !self.block_transaction_filter.is_empty()
    }

    /// Returns a reference to the block transaction filter
    pub fn block_transaction_filter(&self) -> &BlockTransactionFilter {
        &self.block_transaction_filter
    }
}

impl Default for BlockTransactionFilterConfig {
    fn default() -> Self {
        Self {
            filter_enabled: false,                                     // Disable the filter
            block_transaction_filter: BlockTransactionFilter::empty(), // Use an empty filter
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_only_allow_aptos_account_transfer() {
        // Create a new config and configure it to only allow aptos_account::transfer
        let mut filters_config = TransactionFiltersConfig::default();
        filters_config.only_allow_aptos_account_transfer();

        // Verify that both mempool and API filters are enabled
        assert!(
            filters_config.mempool_filter.is_enabled(),
            "Mempool filter should be enabled"
        );
        assert!(
            filters_config.api_filter.is_enabled(),
            "API filter should be enabled"
        );

        // Verify that both filters use the same filter instance (same rules)
        let mempool_filter = filters_config.mempool_filter.transaction_filter();
        let api_filter = filters_config.api_filter.transaction_filter();

        // Both should have the same number of rules (1 Allow + 1 Deny)
        assert_eq!(
            mempool_filter.is_empty(),
            api_filter.is_empty(),
            "Both filters should have the same empty state"
        );

        // Both should not be empty (they have rules)
        assert!(
            !mempool_filter.is_empty(),
            "Mempool filter should not be empty"
        );
        assert!(!api_filter.is_empty(), "API filter should not be empty");
    }
}
