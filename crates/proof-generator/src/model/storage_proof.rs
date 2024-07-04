use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageProof {
    pub key: String,
    pub value: String,
    pub proof: Vec<String>,
}
