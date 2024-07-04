use serde::{Deserialize, Serialize};

use crate::model::storage_proof::StorageProof;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    pub address: String,
    pub balance: String,
    pub code_hash: String,
    pub nonce: String,
    pub storage_hash: String,
    pub account_proof: Vec<String>,
    pub storage_proof: Vec<StorageProof>,
    pub len_proof: usize,
    pub state_root: String,
}
