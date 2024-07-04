use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountProof {
    pub address: String,
    pub balance: String,
    pub code_hash: String,
    pub nonce: u64,
    pub storage_hash: String,
    pub bytes: Vec<usize>,
    pub data: Vec<String>,
}
