use primitive_types::U256;
use proof_generator::model::{account_proof::AccountProof, storage_proof::StorageProof};
use starknet::{
    accounts::{Account, Call, ExecutionEncoding, SingleOwnerAccount},
    core::{
        types::{BlockId, BlockTag, Felt, FunctionCall, InvokeTransactionResult},
        utils::get_selector_from_name,
    },
    macros::felt,
    providers::{
        jsonrpc::{HttpTransport, JsonRpcClient},
        Provider, Url,
    },
    signers::LocalWallet,
};

use crate::{
    error::HandlerError,
    util::{get_high_and_low, prepare_array_data},
};

pub struct FactRegistry {
    provider: JsonRpcClient<HttpTransport>,
    signer: LocalWallet,
    fact_registry: Felt,
    owner_account: Felt,
}

#[allow(dead_code)]
impl FactRegistry {
    pub fn new(rpc: &str, fact_registry: Felt, signer: LocalWallet, owner_account: Felt) -> Self {
        let url = Url::parse(rpc).unwrap();
        println!("eth rpc url: {:?}", url);
        let provider = JsonRpcClient::new(HttpTransport::new(url));

        Self {
            provider,
            signer,
            fact_registry,
            owner_account,
        }
    }

    pub async fn prove_storage(
        &self,
        block_number: u64,
        account_address: U256,
        storage_proof: StorageProof,
        slot: String,
    ) -> Result<InvokeTransactionResult, HandlerError> {
        let (slot_high, slot_low) = get_high_and_low(slot.clone());

        let entry_point_selector = get_selector_from_name("prove_storage")?;

        // Convert block_number to Felt directly
        let block_number_felt = Felt::from(block_number);

        // Convert account_address to bytes and then to Felt
        let mut account_address_bytes = [0u8; 32];
        account_address.to_big_endian(&mut account_address_bytes);
        let account_address_felt = Felt::from_bytes_be_slice(&account_address_bytes);

        // Convert slot parts to Felt
        let slot_low_felt = Felt::from_bytes_be_slice(&slot_low.to_be_bytes());
        let slot_high_felt = Felt::from_bytes_be_slice(&slot_high.to_be_bytes());

        // Process the proof
        let proof_data: Vec<Felt> = storage_proof
            .proof
            .iter()
            .map(|proof_element| {
                let bytes = hex::decode(proof_element.trim_start_matches("0x"))
                    .map_err(|e| HandlerError::HexDecodeError(e.to_string()))?;
                Ok(Felt::from_bytes_be_slice(&bytes))
            })
            .collect::<Result<Vec<Felt>, HandlerError>>()?;

        let proof_len = Felt::from(proof_data.len());

        let mut calldata = vec![
            block_number_felt,
            account_address_felt,
            slot_low_felt,
            slot_high_felt,
            proof_len,
        ];

        calldata.extend(proof_data);

        // Add key and value from StorageProof
        let key_felt = Felt::from_hex(&storage_proof.key)
            .map_err(|e| HandlerError::FeltConversionError(e.to_string()))?;
        let value_felt = Felt::from_hex(&storage_proof.value)
            .map_err(|e| HandlerError::FeltConversionError(e.to_string()))?;

        calldata.push(key_felt);
        calldata.push(value_felt);

        self.invoke(entry_point_selector, calldata).await
    }

    pub async fn prove_account(
        &self,
        block_number: u64,
        account_proof: AccountProof,
    ) -> Result<InvokeTransactionResult, HandlerError> {
        println!("Starting prove_account for block number: {}", block_number);

        println!("Preparing bytes data");
        println!("account_proof.bytes: {:?}", account_proof.bytes);
        println!("Number of bytes: {}", account_proof.bytes.len());
        let bytes_vec: Vec<String> = account_proof
            .bytes
            .into_iter()
            .map(|b| b.to_string())
            .collect();
        println!("Bytes as strings: {:?}", bytes_vec);

        // println!("Calling prepare_array_data for bytes");
        // let (bytes_len, mut bytes) = prepare_array_data(bytes_vec)?;

        println!("Preparing account proof data");
        println!("account_proof.data: {:?}", account_proof.data);
        println!("Number of data elements: {}", account_proof.data.len());

        println!("Calling prepare_array_data for data");
        let (mut bytes, mut proof) = prepare_array_data(account_proof.data)?;

        let entry_point_selector = get_selector_from_name("prove_account")?;

        let mut calldata = Vec::new();

        calldata.push(0.into());
        calldata.push(Felt::from_hex(&account_proof.address).unwrap());
        calldata.push(block_number.into());

        calldata.push(bytes.len().into());
        calldata.append(&mut bytes);
        calldata.push(proof.len().into());
        calldata.append(&mut proof);

        println!("Calldata prepared, invoking contract");
        println!("Calldata: {:?}", calldata);

        let result = self.invoke(entry_point_selector, calldata).await;

        match &result {
            Ok(tx_result) => {
                tracing::info!("Contract invocation successful");
                tracing::debug!("Transaction result: {:?}", tx_result);
            }
            Err(e) => {
                tracing::error!("Contract invocation failed: {:?}", e);
            }
        }
        result
        // // Mock result for debugging
        // let mock_result = InvokeTransactionResult {
        //     transaction_hash: felt!("0x123"),
        // };
        // println!("Mock result: {:?}", mock_result);
        // Ok(mock_result)
    }

    pub async fn get_storage(
        &self,
        block_number: u64,
        account_address: U256,
        slot: String,
    ) -> Result<Vec<Felt>, HandlerError> {
        let (slot_high, slot_low) = get_high_and_low(slot.clone());
        let entry_point_selector = get_selector_from_name("get_storage")?;

        // Convert block_number to Felt directly
        let block_number_felt = Felt::from(block_number);

        // Convert account_address to bytes and then to Felt
        let mut account_address_bytes = [0u8; 32];
        account_address.to_big_endian(&mut account_address_bytes);
        let account_address_felt = Felt::from_bytes_be_slice(&account_address_bytes);

        // Convert slot parts to Felt
        let slot_low_felt = Felt::from_bytes_be_slice(&slot_low.to_be_bytes());
        let slot_high_felt = Felt::from_bytes_be_slice(&slot_high.to_be_bytes());

        let calldata = vec![
            block_number_felt,
            account_address_felt,
            slot_low_felt,
            slot_high_felt,
        ];

        self.call(entry_point_selector, calldata).await
    }

    pub async fn get_verified_account_hash(
        &self,
        block_number: u64,
        account_address: Felt,
    ) -> Result<Vec<Felt>, HandlerError> {
        tracing::info!("Entering get_verified_account_hash");
        let entry_point_selector = get_selector_from_name("get_verified_account_storage_hash")?;
        let calldata = vec![account_address, block_number.into()];
        tracing::info!(
            "Calldata prepared for get_verified_account_storage_hash: {:?}",
            calldata
        );

        self.call(entry_point_selector, calldata).await
    }

    async fn call(
        &self,
        entry_point_selector: Felt,
        calldata: Vec<Felt>,
    ) -> Result<Vec<Felt>, HandlerError> {
        self.provider
            .call(
                FunctionCall {
                    contract_address: self.fact_registry,
                    entry_point_selector,
                    calldata,
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await
            .map_err(HandlerError::ProviderError)
    }

    async fn invoke(
        &self,
        entry_point_selector: Felt,
        calldata: Vec<Felt>,
    ) -> Result<InvokeTransactionResult, HandlerError> {
        let chain_id = self.provider.chain_id().await?;
        let mut account = SingleOwnerAccount::new(
            &self.provider,
            &self.signer,
            self.owner_account,
            chain_id,
            ExecutionEncoding::New,
        );
        account.set_block_id(BlockId::Tag(BlockTag::Latest));

        // let nonce = self
        //     .provider
        //     .get_nonce((BlockId::Tag(BlockTag::Latest)), self.fact_registry)
        //     .await
        //     .map_err(HandlerError::ProviderError)?;
        //
        account
            .execute_v1(vec![Call {
                to: self.fact_registry,
                selector: entry_point_selector,
                calldata,
            }])
            .max_fee(felt!("1000000000000000000"))
            .send()
            .await
            .map_err(HandlerError::AccountError)
    }
}
