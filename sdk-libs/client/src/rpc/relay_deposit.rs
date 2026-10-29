use solana_address::Address;
use spr_event::EncryptedRingDepositData;
use spr_instruction::instruction::{DepositAsset, DepositSplAccounts};
use spr_keypair::{ShieldedAddress, SHIELDED_ADDRESS_LEN};
use wincode::{SchemaRead, SchemaWrite};
use zeroize::{Zeroize, Zeroizing};

use super::RelayProofInputsError;

pub struct RelayDepositInputs {
    pub ring_program_id: Address,
    pub tree: Address,
    pub depositor: Address,
    pub recipient: ShieldedAddress,
    pub asset: DepositAsset,
    pub amount: u64,
    pub view_tag: [u8; 32],
    /// The auditor capsule prefixes the recipient ciphertext.
    pub encrypted: EncryptedRingDepositData,
    pub blinding_secret: Zeroizing<[u8; 32]>,
    /// Ephemeral secret of the auditor capsule in `encrypted`.
    pub audit_ephemeral_key: Zeroizing<[u8; 32]>,
}

#[derive(SchemaWrite, SchemaRead)]
struct DepositWire {
    ring_program_id: Address,
    tree: Address,
    depositor: Address,
    recipient: [u8; SHIELDED_ADDRESS_LEN],
    asset: AssetWire,
    amount: u64,
    view_tag: [u8; 32],
    encrypted: EncryptedRingDepositData,
    blinding_secret: [u8; 32],
    audit_ephemeral_key: [u8; 32],
}

impl Drop for DepositWire {
    fn drop(&mut self) {
        self.blinding_secret.zeroize();
        self.audit_ephemeral_key.zeroize();
    }
}

#[derive(SchemaWrite, SchemaRead)]
#[wincode(tag_encoding = "u8")]
enum AssetWire {
    Sol,
    Spl {
        mint: Address,
        user_token: Address,
        token_program: Address,
    },
}

impl RelayDepositInputs {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RelayProofInputsError> {
        let wire = DepositWire {
            ring_program_id: self.ring_program_id,
            tree: self.tree,
            depositor: self.depositor,
            recipient: self.recipient.to_bytes(),
            asset: match self.asset {
                DepositAsset::Sol => AssetWire::Sol,
                DepositAsset::Spl(spl) => AssetWire::Spl {
                    mint: spl.mint,
                    user_token: spl.user_token,
                    token_program: spl.token_program,
                },
            },
            amount: self.amount,
            view_tag: self.view_tag,
            encrypted: self.encrypted.clone(),
            blinding_secret: *self.blinding_secret,
            audit_ephemeral_key: *self.audit_ephemeral_key,
        };
        Ok(Zeroizing::new(wincode::serialize(&wire)?))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RelayProofInputsError> {
        let wire: DepositWire = wincode::deserialize_exact(bytes)?;
        Ok(Self {
            ring_program_id: wire.ring_program_id,
            tree: wire.tree,
            depositor: wire.depositor,
            recipient: ShieldedAddress::from_bytes(&wire.recipient)?,
            asset: match wire.asset {
                AssetWire::Sol => DepositAsset::Sol,
                AssetWire::Spl {
                    mint,
                    user_token,
                    token_program,
                } => DepositAsset::Spl(DepositSplAccounts {
                    mint,
                    user_token,
                    token_program,
                }),
            },
            amount: wire.amount,
            view_tag: wire.view_tag,
            encrypted: wire.encrypted.clone(),
            blinding_secret: Zeroizing::new(wire.blinding_secret),
            audit_ephemeral_key: Zeroizing::new(wire.audit_ephemeral_key),
        })
    }
}
