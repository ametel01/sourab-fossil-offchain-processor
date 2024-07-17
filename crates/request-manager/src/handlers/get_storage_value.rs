use axum::{extract::State, response::IntoResponse, Json};
use dotenv::dotenv;
use reqwest::StatusCode;
use serde::Deserialize;
use std::str::FromStr;

use crate::state::AppState;
use proof_generator::{
    controller::eth_blocks::call_eth_blocks_api,
    model::{
        account_proof::AccountProof, eth_rpc::BlockNumber, hex::HexString, proof::Proof,
        storage_proof::StorageProof,
    },
};

use ethers::{
    middleware::Middleware,
    providers::{Http, Provider},
    types::{BlockId, H160, H256, U256},
};
use starknet::{
    core::types::Felt,
    signers::{LocalWallet, SigningKey},
};
use starknet_handler::{
    fact_registry::fact_registry::FactRegistry, l1_headers_store::l1_headers_store::L1HeadersStore,
};
// use proof_generator::model::proof::{Proof, StorageProof};

#[derive(Debug, Deserialize, Clone)]
pub struct StorageRequest {
    pub block_number: u64,
    pub account_address: String,
    pub slot: String,
    pub storage_keys: Vec<String>,
}

async fn fetch_env_variable(key: &str) -> String {
    dotenv::var(key).unwrap()
}

async fn init_signer() -> LocalWallet {
    let private_key = fetch_env_variable("KATANA_8_PRIVATE_KEY").await;
    let private_key_felt = Felt::from_hex(&private_key).unwrap();
    let signing_key = SigningKey::from_secret_scalar(private_key_felt);
    LocalWallet::from(signing_key)
}

async fn init_contracts(
    signer: LocalWallet,
    owner_account: Felt,
) -> (FactRegistry, L1HeadersStore) {
    let fact_registry_address =
        Felt::from_hex(&fetch_env_variable("FACT_REGISTRY_ADDRESS").await).unwrap();
    let l1_headers_store_address =
        Felt::from_hex(&fetch_env_variable("L1_HEADERS_STORE_ADDRESS").await).unwrap();
    let starknet_rpc = fetch_env_variable("STARKNET_RPC").await;

    let fact_registry_contract = FactRegistry::new(
        &starknet_rpc,
        fact_registry_address,
        signer.clone(),
        owner_account,
    );
    let l1_headers_store_contract = L1HeadersStore::new(
        &starknet_rpc,
        l1_headers_store_address,
        signer,
        owner_account,
    );

    (fact_registry_contract, l1_headers_store_contract)
}

async fn handle_storage_request(
    fact_registry_contract: &FactRegistry,
    input: &StorageRequest,
) -> Result<U256, StatusCode> {
    tracing::info!("Request storage");
    let response_storage = fact_registry_contract
        .get_storage(
            input.block_number,
            U256::from_str(&input.account_address).unwrap(),
            input.slot.clone(),
        )
        .await;

    match response_storage {
        Ok(res) => {
            tracing::info!("Result response_storage: {:?}", res);
            if res.len() == 2 {
                let mut value = U256::from(0);
                for (i, field_element) in res.iter().enumerate() {
                    let big_int = U256::from_dec_str(&field_element.to_string()).unwrap();
                    value += big_int << (i * 128);
                }
                if value != U256::from(1) {
                    return Ok(value);
                }
            }
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(err) => {
            tracing::error!("Error response_storage: {:?}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn handle_state_root_request(
    l1_headers_store_contract: &L1HeadersStore,
    input: &StorageRequest,
    app_state: &AppState,
) -> Result<(), StatusCode> {
    tracing::info!("Request state_root by calling `get_state_root` in l1_headers_store");

    match l1_headers_store_contract
        .get_state_root(input.block_number)
        .await
    {
        Ok(res) => {
            let mut value = U256::from(0);
            for (i, field_element) in res.iter().enumerate() {
                let big_int = U256::from_dec_str(&field_element.to_string()).unwrap();
                value += big_int << (i * 128);
            }
            tracing::info!("Result state_root: {:?}", value);

            if value == U256::from(0) {
                let api_input = BlockNumber {
                    block_number: HexString::new(&format!("0x{:x}", input.block_number)),
                };
                let response =
                    call_eth_blocks_api(State(app_state.client.clone()), Json(api_input))
                        .await
                        .into_response();

                if response.status() == StatusCode::BAD_REQUEST {
                    tracing::error!("Bad request error: {:?}", response);
                    return Err(StatusCode::BAD_REQUEST);
                }

                let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .map_err(|err| {
                        tracing::error!("Error converting response body to bytes: {:?}", err);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                if bytes.len() < 68 {
                    tracing::error!(
                        "Response body too short, expected at least 68 bytes, got {}",
                        bytes.len()
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }

                let state_root = String::from_utf8(bytes[1..67].to_vec()).map_err(|err| {
                    tracing::error!("Error converting bytes to string: {:?}", err);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                l1_headers_store_contract
                    .store_state_root(input.block_number, state_root)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            }
            Ok(())
        }
        Err(err) => {
            tracing::info!("No state_root available, {}", err);
            let api_input = BlockNumber {
                block_number: HexString::new(&format!("0x{:x}", input.block_number)),
            };
            let response = call_eth_blocks_api(State(app_state.client.clone()), Json(api_input))
                .await
                .into_response();

            if response.status() == StatusCode::BAD_REQUEST {
                tracing::error!("Bad request error: {:?}", response);
                return Err(StatusCode::BAD_REQUEST);
            }

            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .map_err(|err| {
                    tracing::error!("Error converting response body to bytes: {:?}", err);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

            let state_root =
                String::from_utf8(bytes.to_vec()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let state_root = state_root.trim_matches('"').to_string();

            l1_headers_store_contract
                .store_state_root(input.block_number, state_root)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(())
        }
    }
}

async fn handle_proof_request(
    input: &StorageRequest,
    app_state: &AppState,
) -> Result<Proof, StatusCode> {
    tracing::info!("Handle proof: Request eth_getProof");
    tracing::info!("Input: {:?}", input);

    let provider = match Provider::<Http>::try_from(app_state.eth_rpc_url.as_str()) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to create provider: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let address = match H160::from_str(&input.account_address) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Failed to parse account address: {:?}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let storage_keys: Vec<H256> = input
        .storage_keys
        .iter()
        .map(|key| {
            let padded_key = format!("{:0>64}", key.trim_start_matches("0x"));
            H256::from_str(&padded_key).map_err(|e| {
                tracing::error!("Failed to parse storage key {}: {:?}", key, e);
                StatusCode::BAD_REQUEST
            })
        })
        .collect::<Result<Vec<H256>, StatusCode>>()?;

    let block_number = BlockId::Number(input.block_number.into());

    tracing::info!("Requesting proof for address: {:?}", address);
    tracing::info!("Requesting proof for storage_keys: {:?}", storage_keys);

    match provider
        .get_proof(address, storage_keys, Some(block_number))
        .await
    {
        Ok(proof) => {
            let storage_proof = proof
                .storage_proof
                .into_iter()
                .map(|sp| StorageProof {
                    key: format!("{:?}", sp.key),
                    value: sp.value.to_string(),
                    proof: sp.proof.iter().map(|p| format!("{:?}", p)).collect(),
                })
                .collect();

            let converted_proof = Proof {
                address: format!("{:?}", proof.address),
                balance: proof.balance.to_string(),
                code_hash: format!("{:?}", proof.code_hash),
                nonce: proof.nonce.to_string(),
                storage_hash: format!("{:?}", proof.storage_hash),
                account_proof: proof
                    .account_proof
                    .iter()
                    .map(|p| format!("{:?}", p))
                    .collect(),
                storage_proof,
                len_proof: proof.account_proof.len(),
                state_root: format!("{:?}", proof.storage_hash), // Using storage_hash as state_root
            };
            tracing::info!("Proof: {:?}", converted_proof);
            Ok(converted_proof)
        }
        Err(err) => {
            tracing::error!("Error getting proof: {:?}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn verify_account_proof(
    fact_registry_contract: &FactRegistry,
    input: &StorageRequest,
    eth_proof: &Proof,
) -> Result<(), StatusCode> {
    tracing::info!("Entering verify_account_proof");

    // Print raw input address for debugging
    tracing::debug!("Raw account address input: {:?}", input.account_address);

    let account_address = match Felt::from_str(&input.account_address) {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!("Failed to parse account address: {:?}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    tracing::info!("Parsed account address: {:?}", account_address);

    match fact_registry_contract
        .get_verified_account_hash(input.block_number, account_address)
        .await
    {
        Ok(hash) => {
            if hash == vec![Felt::from(0), Felt::from(0)] {
                tracing::info!("Account not verified yet");
            } else {
                tracing::info!("Account already verified with hash: {:?}", hash);
                return Ok(());
            }
        }
        Err(e) => {
            tracing::info!("error: {:?}", e);
        }
    }

    tracing::info!("Preparing to verify account on Starknet");

    let account_proof = AccountProof {
        address: eth_proof.address.clone(),
        balance: eth_proof.balance.clone(),
        code_hash: eth_proof.code_hash.clone(),
        storage_hash: eth_proof.storage_hash.clone(),
        nonce: u64::from_str(&eth_proof.nonce.clone()).unwrap(),
        bytes: vec![], // You might need to fill this if required
        data: eth_proof.account_proof.clone(),
    };

    tracing::info!("Created AccountProof: {:?}", account_proof);
    tracing::info!("Calling prove_account");

    // Ensure the call to prove_account is logged
    match fact_registry_contract
        .prove_account(input.block_number, account_proof)
        .await
    {
        Ok(res) => {
            tracing::info!("Prove account response: {:?}", res);
            Ok(())
        }
        Err(err) => {
            tracing::error!("Error while verifying the account proof: {:?}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn verify_storage_proof(
    fact_registry_contract: &FactRegistry,
    input: &StorageRequest,
    eth_proof: Proof,
) -> Result<axum::http::Response<axum::body::Body>, StatusCode> {
    tracing::info!("Verifying the storage proof");

    // Check if there's at least one storage proof
    if eth_proof.storage_proof.is_empty() {
        tracing::error!("No storage proof found");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Take the first storage proof
    let storage_proof = eth_proof.storage_proof.into_iter().next().unwrap();

    fact_registry_contract
        .prove_storage(
            input.block_number,
            U256::from_str(&input.account_address).unwrap(),
            storage_proof,
            input.slot.clone(),
        )
        .await
        .map(|res| (StatusCode::OK, Json(&res)).into_response())
        .map_err(|err| {
            tracing::error!("Error while verifying the storage proof: {:?}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

pub async fn get_storage_value(
    State(app_state): State<AppState>,
    Json(input): Json<StorageRequest>,
) -> axum::http::Response<axum::body::Body> {
    dotenv().ok();

    let signer = init_signer().await;
    let owner_account = Felt::from_hex(&fetch_env_variable("KATANA_8_ADDRESS").await).unwrap();
    let (fact_registry_contract, l1_headers_store_contract) =
        init_contracts(signer, owner_account).await;

    if let Ok(value) = handle_storage_request(&fact_registry_contract, &input).await {
        return (StatusCode::OK, Json(&value)).into_response();
    }

    if let Err(status_code) =
        handle_state_root_request(&l1_headers_store_contract, &input, &app_state).await
    {
        return (status_code, Json("Error requesting state root")).into_response();
    }

    let eth_proof = match handle_proof_request(&input, &app_state).await {
        Ok(proof) => proof,
        Err(status_code) => {
            return (status_code, Json("Error requesting eth_getProof")).into_response()
        }
    };

    if let Err(status_code) =
        verify_account_proof(&fact_registry_contract, &input, &eth_proof).await
    {
        return (status_code, Json("Error verifying account proof")).into_response();
    }

    match verify_storage_proof(&fact_registry_contract, &input, eth_proof).await {
        Ok(response) => response,
        Err(status_code) => (status_code, Json("Error verifying storage proof")).into_response(),
    }
}
