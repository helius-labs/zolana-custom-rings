use spr_hasher::primitives::hash_bytes;
use spr_transaction::{AssetRegistry, Mint, TransactionError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingAssets {
    registry: AssetRegistry,
    fields: Vec<([u8; 32], Mint)>,
}

impl RingAssets {
    /// `registered` excludes SOL, the registry refuses its reserved id.
    pub fn new(registered: impl IntoIterator<Item = Mint>) -> Result<Self, TransactionError> {
        let mut registry = AssetRegistry::default();
        let mut fields = vec![(hash_bytes(Mint::SOL.asset.as_array())?, Mint::SOL)];
        for mint in registered {
            registry.insert(mint.asset_id, mint.asset)?;
            fields.push((hash_bytes(mint.asset.as_array())?, mint));
        }
        Ok(Self { registry, fields })
    }

    pub fn registry(&self) -> &AssetRegistry {
        &self.registry
    }

    pub fn mints(&self) -> impl Iterator<Item = &Mint> {
        self.fields.iter().map(|(_, mint)| mint)
    }

    pub fn by_field(&self, field: &[u8; 32]) -> Option<Mint> {
        self.fields
            .iter()
            .find_map(|(held, mint)| (held == field).then_some(*mint))
    }

    pub fn fields(&self) -> impl Iterator<Item = &([u8; 32], Mint)> {
        self.fields.iter()
    }
}
