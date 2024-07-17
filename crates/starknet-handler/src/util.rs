use std::str::FromStr;

use primitive_types::U256;
use starknet::core::types::Felt;

use crate::error::HandlerError;

pub fn get_high_and_low(state_root: String) -> (u128, u128) {
    let state_root = U256::from_str(state_root.as_str()).unwrap();
    let state_root_low = state_root.low_u128();
    let state_root_high: u128 = (state_root >> 128).as_u128();
    (state_root_high, state_root_low)
}

pub fn prepare_array_data<T>(data: Vec<T>) -> Result<(Vec<Felt>, Vec<Felt>), HandlerError>
where
    T: AsRef<str> + ToString,
{
    println!("Entering prepare_array_data");
    println!("Preparing array data with {} elements", data.len());

    let mut lengths = Vec::with_capacity(data.len());
    let mut felt_data = Vec::new();

    for (index, item) in data.iter().enumerate() {
        let item_str = item.to_string();
        if item_str.starts_with("Bytes(") && item_str.ends_with(')') {
            // Extract the hex string
            let hex_str = &item_str[6..item_str.len() - 1];
            println!("Extracted hex string at index {}: {}", index, hex_str);
            // Remove '0x' prefix if present
            let clean_hex = hex_str.trim_start_matches("0x");
            println!("Cleaned hex string at index {}: {}", index, clean_hex);
            // Pad with a leading zero if necessary to ensure even length
            let padded_hex = if clean_hex.len() % 2 != 0 {
                format!("0{}", clean_hex)
            } else {
                clean_hex.to_string()
            };
            println!("Padded hex at index {}: {}", index, padded_hex);
            // Convert hex to bytes
            let bytes = hex::decode(&padded_hex).map_err(|e| {
                tracing::error!("Failed to decode hex at index {}: {:?}", index, e);
                HandlerError::FieldElementParseError(format!(
                    "Hex decode error at index {}: {}",
                    index, e
                ))
            })?;
            // Convert bytes to u64 chunks
            let mut u64_chunks = Vec::new();
            let mut padded_bytes = bytes.clone();
            while padded_bytes.len() % 8 != 0 {
                padded_bytes.push(0); // Pad with zeros if not a multiple of 8
            }
            for chunk in padded_bytes.chunks(8) {
                let mut array = [0u8; 8];
                array.copy_from_slice(chunk);
                u64_chunks.push(u64::from_be_bytes(array));
            }

            // Add the length of the byte array
            lengths.push(Felt::from(bytes.len() as u64));

            // Convert u64 chunks to Felts and add to the felt_data
            for u64_chunk in u64_chunks {
                felt_data.push(Felt::from(u64_chunk));
            }
        } else {
            return Err(HandlerError::FieldElementParseError(format!(
                "Invalid item at index {}: {}",
                index, item_str
            )));
        }
    }

    tracing::info!("Successfully prepared array data");
    Ok((lengths, felt_data))
}
