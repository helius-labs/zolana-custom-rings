use std::str::FromStr;

use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedTransactionWithStatusMeta, UiConfirmedBlock,
    UiInstruction, UiTransactionStatusMeta,
};
use spr_indexer_api::Hash;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub program_id: Address,
    pub data: Vec<u8>,
    pub accounts: Vec<Address>,
    pub stack_height: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionGroup {
    pub outer_instruction: Instruction,
    pub inner_instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionInfo {
    pub instruction_groups: Vec<InstructionGroup>,
    pub signature: Signature,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    pub metadata: BlockMetadata,
    pub transactions: Vec<TransactionInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BlockMetadata {
    pub slot: u64,
    pub parent_slot: u64,
    pub block_time: i64,
    pub blockhash: Hash,
    pub parent_blockhash: Hash,
    pub block_height: u64,
}

impl BlockMetadata {
    pub fn is_parent_of(&self, child: &Self) -> bool {
        child.parent_slot == self.slot && child.parent_blockhash == self.blockhash
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlockError {
    #[error("block has no {0}")]
    MissingField(&'static str),
    #[error("block {field} is not a hash")]
    InvalidHash { field: &'static str },
    #[error("transaction does not decode")]
    UndecodableTransaction,
    #[error("transaction has no status metadata")]
    MissingMetadata,
    #[error("transaction has no signature")]
    MissingSignature,
    #[error("{context} index {index} is out of bounds for {len} accounts")]
    AccountOutOfBounds {
        context: &'static str,
        index: usize,
        len: usize,
    },
    #[error("inner instruction group {0} has no outer instruction")]
    InnerGroupOutOfBounds(u8),
    #[error("inner instruction data is not base58")]
    InvalidInnerData,
    #[error("parsed inner instructions are not supported")]
    ParsedInstruction,
    #[error("loaded address {0} is not an address")]
    InvalidLoadedAddress(String),
    #[error("transaction loads lookup table accounts its metadata does not list")]
    MissingLoadedAddresses,
}

impl BlockInfo {
    pub fn parse(block: UiConfirmedBlock, slot: u64) -> Result<Self, BlockError> {
        let UiConfirmedBlock {
            parent_slot,
            block_time,
            transactions,
            blockhash,
            previous_blockhash,
            block_height,
            ..
        } = block;
        let hash = |value: &str, field| {
            Hash::try_from(value).map_err(|_| BlockError::InvalidHash { field })
        };
        Ok(Self {
            transactions: transactions
                .unwrap_or_default()
                .into_iter()
                .map(TransactionInfo::parse)
                .collect::<Result<_, _>>()?,
            metadata: BlockMetadata {
                slot,
                parent_slot,
                block_time: block_time.ok_or(BlockError::MissingField("block time"))?,
                blockhash: hash(&blockhash, "blockhash")?,
                parent_blockhash: hash(&previous_blockhash, "previous blockhash")?,
                block_height: block_height.ok_or(BlockError::MissingField("block height"))?,
            },
        })
    }
}

impl TransactionInfo {
    pub fn parse(transaction: EncodedTransactionWithStatusMeta) -> Result<Self, BlockError> {
        let EncodedTransactionWithStatusMeta {
            transaction, meta, ..
        } = transaction;
        let transaction: VersionedTransaction = transaction
            .decode()
            .ok_or(BlockError::UndecodableTransaction)?;
        let meta = meta.ok_or(BlockError::MissingMetadata)?;
        let signature = *transaction
            .signatures
            .first()
            .ok_or(BlockError::MissingSignature)?;
        Ok(Self {
            error: meta.err.as_ref().map(ToString::to_string),
            instruction_groups: instruction_groups(&transaction, &meta)?,
            signature,
        })
    }
}

fn instruction_groups(
    transaction: &VersionedTransaction,
    meta: &UiTransactionStatusMeta,
) -> Result<Vec<InstructionGroup>, BlockError> {
    let keys = account_keys(transaction, meta)?;
    let resolve = |indices: &[u8], context| {
        indices
            .iter()
            .map(|index| account(&keys, usize::from(*index), context))
            .collect::<Result<Vec<_>, _>>()
    };
    let mut groups = transaction
        .message
        .instructions()
        .iter()
        .map(|ix| {
            Ok(InstructionGroup {
                outer_instruction: Instruction {
                    program_id: account(
                        &keys,
                        usize::from(ix.program_id_index),
                        "outer instruction program id",
                    )?,
                    data: ix.data.clone(),
                    accounts: resolve(&ix.accounts, "outer instruction account")?,
                    stack_height: Some(1),
                },
                inner_instructions: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, BlockError>>()?;
    if let OptionSerializer::Some(inner) = &meta.inner_instructions {
        for inner in inner {
            let group = groups
                .get_mut(usize::from(inner.index))
                .ok_or(BlockError::InnerGroupOutOfBounds(inner.index))?;
            for instruction in &inner.instructions {
                let UiInstruction::Compiled(compiled) = instruction else {
                    return Err(BlockError::ParsedInstruction);
                };
                group.inner_instructions.push(Instruction {
                    program_id: account(
                        &keys,
                        usize::from(compiled.program_id_index),
                        "inner instruction program id",
                    )?,
                    data: bs58::decode(&compiled.data)
                        .into_vec()
                        .map_err(|_| BlockError::InvalidInnerData)?,
                    accounts: resolve(&compiled.accounts, "inner instruction account")?,
                    stack_height: compiled.stack_height,
                });
            }
        }
    }
    Ok(groups)
}

/// Static keys, then lookup table addresses with writable before readonly.
fn account_keys(
    transaction: &VersionedTransaction,
    meta: &UiTransactionStatusMeta,
) -> Result<Vec<Address>, BlockError> {
    let message = &transaction.message;
    let mut keys = Vec::from(message.static_account_keys());
    match &meta.loaded_addresses {
        OptionSerializer::Some(loaded) => {
            for address in loaded.writable.iter().chain(&loaded.readonly) {
                keys.push(
                    Address::from_str(address)
                        .map_err(|_| BlockError::InvalidLoadedAddress(address.clone()))?,
                );
            }
        }
        OptionSerializer::None | OptionSerializer::Skip => {
            if message
                .address_table_lookups()
                .is_some_and(|lookups| !lookups.is_empty())
            {
                return Err(BlockError::MissingLoadedAddresses);
            }
        }
    }
    Ok(keys)
}

fn account(keys: &[Address], index: usize, context: &'static str) -> Result<Address, BlockError> {
    keys.get(index)
        .copied()
        .ok_or(BlockError::AccountOutOfBounds {
            context,
            index,
            len: keys.len(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Devnet slot 492480571.
    const VERSION_1_TRANSACTION: &str = r#"{
        "meta": {
            "computeUnitsConsumed": 150,
            "costUnits": 1481,
            "err": null,
            "fee": 10000,
            "innerInstructions": [],
            "loadedAddresses": {"readonly": [], "writable": []},
            "logMessages": [
                "Program 11111111111111111111111111111111 invoke [1]",
                "Program 11111111111111111111111111111111 success"
            ],
            "postBalances": [186075591481, 1000000, 1],
            "postTokenBalances": [],
            "preBalances": [186076601481, 0, 1],
            "preTokenBalances": [],
            "rewards": null,
            "status": {"Ok": null}
        },
        "transaction": [
            "gQEAAQ8AAADy9w1C57Jkve55/n0evk8h1V29Nq+WNjW/apyV99YdCAEDPJBEOvrHznm+JIY1gvt1x6JkQoct90T995JbS/vOpH2QdlSnm2Um+5lt81NwkwX9AGps4zj4PfkCUwgZYyu/GQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiBMAAAAAAADQBwAAAAABAAICDAAAAQIAAABAQg8AAAAAAFFfm76ICVd7iVN/uBVLqSdY6ZrZH0apLSUPPd+v+d9AsaMhO7GBd3wzf8mDxqeAvlE/UCIGuihGS/8w40CSDAE=",
            "base64"
        ],
        "version": 1
    }"#;

    // Devnet slot 508799716, a version 0 shielded-pool deposit without lookup tables.
    const VERSION_0_DEPOSIT: &str = r#"{"meta":{"err":null,"status":{"Ok":null},"fee":5000,"preBalances":[18676128,23930254400,1488440,1488440,1,0,1,1066800,833120,20369267856],"postBalances":[18671128,23930254400,1488440,1488440,1,0,1,1066800,833120,20369267856],"innerInstructions":[{"index":1,"instructions":[{"programIdIndex":9,"accounts":[2,7,3,0],"data":"gvPShZQhKrzGM","stackHeight":2},{"programIdIndex":8,"accounts":[],"data":"2DdzFKysLDBMuANPWmpuTgr2ryZH5x1FSSNwS4CEsHzfUUYutpUUePviBeUMPgHaak9C2bSszk1j7TupcjyEqL6Hfxg2iVRcA8Hu3Gj1JDSreoKxDuu3f2GqRh31fZkFjPC6epFhrXixiPbTgG2TNEEoJjCXNebDpDLJVu5jUgLbr4cP7VmJZkA1itFX2z2CSGS7gvYhZo4AJPAFVZnk7k9NNVox1MMzN1FDwxgrLdEXCMs5pFk4WT97B2yZu2vWYu4HK3X1vz4N5PbFMogKLTB3JW2Rb1vJjFbFoHh9wvMPP5jBRMYg77xvPz6GNv5CuFG7LUkseVLdBmQ7J9DaQVxYTfDbuHH4yEwbXq6bMuCbbkkiC52nxmouhdtAfewMN54uE4y1M3tqRBnqzUV8mQKMX3dKDfiGStZo1AdNzoyL19ehtQxLqzitYBvmhdFBMVpkoTo","stackHeight":2}]}],"logMessages":[],"preTokenBalances":[],"postTokenBalances":[],"rewards":null,"loadedAddresses":{"writable":[],"readonly":[]},"computeUnitsConsumed":40087},"transaction":["AZSgsUs1lwKuk4kV/H6lcBS5a56e8FQWjHKWRlumu0vlil0i9LgZCp+W2nkiVc9Zb0edmu3BVDS6Lew0HeBOTgeAAQAGCsfSAbFW5dtTfOyGP+aa31AAhlraMvr01WNI+HwfXnj4Hk9ymFddIGHbkm/tzOnMxAgnPI/mt9TyQf4neFNRTB3UtGd2T2ab3zqow7rwofyuLXareWMn9SQjQx3JlCGS4/YkxUKmeq/Dvvlm8ae/swUv/lHq63pMEfKVq/jXlR5IAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACRAl70pEGVI/o1tvhbQHyNPcTif6PFmbxDicN9JkzvNgMGRm/lIRcy/+ytunLDm+e8jOW7xfcSayxDmzpAAAAA92q1xD/zyzGxEJO9jRGadeyivT3bWdb+3JLuYwBm9rINBRvfUS7uJgsVS3WBKq3rgM+6NmTWOTdYplwz8jXvPQbd9uHXZaGT2cvhRs7reawctIXtX1s3kTqM9YV+/wCpk3pKuioAJsyweIxrRiy3XifM4ZgELKGS1NLLkjOQgeADBgAFAtDdBgAIBwEACAkHAgNPDwEB/QEAbZ4EBn45csw2BgpGLXxaFYU26Iqa6lt7eNWhoK9/8Qkk8H1n/eQvbYjL1wzVNw1EHdRgxIjipVhTzDNeW10pEkBCDwAAAAAAAAQDAAAFDAIAAAAAAAAAAAAAAAA=","base64"],"version":0}"#;

    // Devnet slot 508799716, four writable and one readonly lookup table account.
    const VERSION_0_WITH_LOOKUPS: &str = r#"{"meta":{"err":null,"status":{"Ok":null},"fee":5000,"preBalances":[49170000,1,833120,6329680,6329680,6329680,6329680,1188720],"postBalances":[49165000,1,833120,6329680,6329680,6329680,6329680,1188720],"innerInstructions":[],"logMessages":[],"preTokenBalances":[],"postTokenBalances":[],"rewards":null,"loadedAddresses":{"writable":["26bQ1aba173cQPgxFZFx4Es8dgXCLryzXmgLpezkxpY9","DuokWvuVUdQqtkCqzxVi9FMEG53S1RgkraSjC2y8tKbc","zsePY4VdVs1LxzziGXUnMjqNJrxqEgLUyzCWUt2uo7D","CMzRZeb4PpDVQVLvvEPcHEtfUEqV8BamPtn2unjkJ589"],"readonly":["EXjycYGbH88NdpgfcEkJqXp33T91NCcSFKiii9SazqAo"]},"computeUnitsConsumed":52124},"transaction":["AeQpRAf0XZzfGoWoD2sf1m7p3P5tjJgE99mMmhC+ll2h34wgXu+a6MkTwsdYQY8BMBFlBHDGeBI5+a9SRyHEaQSAAQACA5lN7tia5v412jQkNc+3acF3EgNzbNNPaZK9mqHQWbKkAwZGb+UhFzL/7K26csOb57yM5bvF9xJrLEObOkAAAACEi6WIL1dWYkvfRO/X7x1ySTrsxLqbiMKiaqVizLDcFJx7XF4pe3jPHCWGNhw1hD1sd7sVaJpHqoimEIM8kH2fBgEABQEAAAIAAQAFAgA1DAACAwAHA0eBsbaguODbBQCR+o3GpCQBjHzHagAAAAAM6BgsI9+xmgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQAAAAAAAAIDAAcER4GxtqC44NsFECoE+YhKBACMfMdqAAAAAAToGCwj37GaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAAAAAAAAgMABwVHgbG2oLjg2wVgPYoHHmcAAIx8x2oAAAAADOgYLCPfsZoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkAAAAAAAACAwAHBkeBsbaguODbBQDKDgu0/wgAjHzHagAAAAAM6BgsI9+xmgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQAAAAAAAAGgsNHgDHZdpgBijSJJ3/eInwm2+5qV9SCpeBaAZBeeLAQuMDI0AQE=","base64"],"version":0}"#;

    fn address(key: &str) -> Address {
        Address::from_str(key).unwrap()
    }

    fn transaction(json: &str) -> EncodedTransactionWithStatusMeta {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn parent_links_require_both_slot_and_hash() {
        let mut field = [0; 32];
        field[31] = 1;
        let parent = BlockMetadata {
            slot: 17,
            blockhash: Hash(field),
            ..Default::default()
        };
        let mut child = BlockMetadata {
            slot: 19,
            parent_slot: 17,
            parent_blockhash: parent.blockhash.clone(),
            ..Default::default()
        };
        assert!(parent.is_parent_of(&child));
        child.parent_blockhash = Hash([2; 32]);
        assert!(!parent.is_parent_of(&child));
        child.parent_blockhash = parent.blockhash.clone();
        child.parent_slot = 18;
        assert!(!parent.is_parent_of(&child));
    }

    #[test]
    fn parses_version_0_transaction_without_lookups() {
        let info = TransactionInfo::parse(transaction(VERSION_0_DEPOSIT)).unwrap();
        assert_eq!(
            info.signature,
            Signature::from_str(
                "3yMGsQ275aG65YsDoWEbNPNnGw7MuCq5MH2ne2PueBvcNGQ7ccKSkwhZgv2GmqXQYfBQpEF8eSvYTXdBKEA1Hn6r",
            )
            .unwrap()
        );
        assert_eq!(info.instruction_groups.len(), 3);
        let deposit = &info.instruction_groups[1];
        assert_eq!(
            deposit.outer_instruction.program_id,
            address("sppU489D7A4U1exNo1oeMGZtLEofq3a6o2fR7UeoWB6")
        );
        assert_eq!(deposit.outer_instruction.data[0], 15);
        assert_eq!(
            deposit.outer_instruction.accounts[0],
            address("33KVhbT4QtdQDrrrGwwThqD47Dh4Q6tA443t9jMNcWFN")
        );
        let emitted = &deposit.inner_instructions[1];
        assert_eq!(emitted.data[0], 14);
        assert_eq!(emitted.stack_height, Some(2));
    }

    #[test]
    fn resolves_lookup_table_accounts_from_loaded_addresses() {
        let info = TransactionInfo::parse(transaction(VERSION_0_WITH_LOOKUPS)).unwrap();
        let accounts: Vec<Vec<Address>> = info
            .instruction_groups
            .iter()
            .skip(2)
            .map(|group| group.outer_instruction.accounts.clone())
            .collect();
        let payer = address("BKSJXEd9nmKPHK6UPVWF2CySZpfK1RoYExBzpiMSuGaX");
        let readonly = address("EXjycYGbH88NdpgfcEkJqXp33T91NCcSFKiii9SazqAo");
        assert_eq!(
            accounts,
            [
                "26bQ1aba173cQPgxFZFx4Es8dgXCLryzXmgLpezkxpY9",
                "DuokWvuVUdQqtkCqzxVi9FMEG53S1RgkraSjC2y8tKbc",
                "zsePY4VdVs1LxzziGXUnMjqNJrxqEgLUyzCWUt2uo7D",
                "CMzRZeb4PpDVQVLvvEPcHEtfUEqV8BamPtn2unjkJ589",
            ]
            .map(|writable| vec![payer, readonly, address(writable)])
        );
    }

    #[test]
    fn rejects_lookup_table_transaction_without_loaded_addresses() {
        let mut encoded = transaction(VERSION_0_WITH_LOOKUPS);
        encoded.meta.as_mut().unwrap().loaded_addresses = OptionSerializer::None;
        assert_eq!(
            TransactionInfo::parse(encoded),
            Err(BlockError::MissingLoadedAddresses)
        );
    }

    #[test]
    fn parses_version_1_transaction() {
        assert_eq!(
            TransactionInfo::parse(transaction(VERSION_1_TRANSACTION)).unwrap(),
            TransactionInfo {
                instruction_groups: vec![InstructionGroup {
                    outer_instruction: Instruction {
                        program_id: address("11111111111111111111111111111111"),
                        data: vec![2, 0, 0, 0, 64, 66, 15, 0, 0, 0, 0, 0],
                        accounts: vec![
                            address("55R41dbRU13QhLpAgha1841wR5M6sAcZhXd4S1LGupBn"),
                            address("AivMvWMKoiXbqxok1xvW7ES5CWr3DG3TYR94iy1SBdBe"),
                        ],
                        stack_height: Some(1),
                    },
                    inner_instructions: Vec::new(),
                }],
                signature: Signature::from_str(
                    "2dMwts34QC98z5E9dt16RcSr793Qe94DSFbgYyZwoT9TEmgNUuYBSNoKdtsV86o5yrR24P143y5o4qoeAyWzZ1Sg",
                )
                .unwrap(),
                error: None,
            }
        );
    }
}
