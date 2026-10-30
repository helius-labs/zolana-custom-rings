/// Per-mint settings stored in the ring's authenticated asset record.
/// Zero disables recipient/withdrawal exemptions, the outflow cap, or the
/// outflow co-sign requirement, respectively.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct MintPolicy {
    pub threshold: u64,
    pub cap: u64,
    pub cosign_above: u64,
    /// Public withdrawal totals at or below this amount need no withdrawal-scoped co-signature.
    pub withdrawal_threshold: u64,
}

impl MintPolicy {
    pub const EMPTY: Self = Self {
        threshold: 0,
        cap: 0,
        cosign_above: 0,
        withdrawal_threshold: 0,
    };

    /// Three unsigned 64-bit amounts, packed into one canonical field.
    pub fn field(self) -> [u8; 32] {
        let mut field = [0; 32];
        field[8..16].copy_from_slice(&self.threshold.to_be_bytes());
        field[16..24].copy_from_slice(&self.cap.to_be_bytes());
        field[24..].copy_from_slice(&self.cosign_above.to_be_bytes());
        field
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let [threshold, cap, cosign_above, withdrawal_threshold] =
            bytemuck::cast::<_, [[u8; 8]; 4]>(bytes).map(u64::from_be_bytes);
        Self {
            threshold,
            cap,
            cosign_above,
            withdrawal_threshold,
        }
    }

    pub fn bytes(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..24].copy_from_slice(&self.field()[8..]);
        bytes[24..].copy_from_slice(&self.withdrawal_threshold.to_be_bytes());
        bytes
    }
}
