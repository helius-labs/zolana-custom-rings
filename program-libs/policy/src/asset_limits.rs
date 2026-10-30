use thiserror::Error;

/// Big endian u64 amounts in field order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct AssetLimits {
    pub sender_cap: u64,
    pub sender_window_slots: u64,
    pub volume_cap: u64,
    pub volume_window_slots: u64,
    pub deposit_cap: u64,
    pub deposit_window_slots: u64,
    pub withdrawal_cap: u64,
    pub withdrawal_window_slots: u64,
}

/// Three u64 amounts per field keep it below 2^192.
const FIELD_AMOUNT_BYTES: usize = 24;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AssetLimitsError {
    #[error("a window cap and its window are not set together")]
    UnpairedWindow,
}

impl AssetLimits {
    pub const LEN: usize = 64;
    pub const FIELDS: usize = Self::LEN.div_ceil(FIELD_AMOUNT_BYTES);

    pub const EMPTY: Self = Self {
        sender_cap: 0,
        sender_window_slots: 0,
        volume_cap: 0,
        volume_window_slots: 0,
        deposit_cap: 0,
        deposit_window_slots: 0,
        withdrawal_cap: 0,
        withdrawal_window_slots: 0,
    };

    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        let [sender_cap, sender_window_slots, volume_cap, volume_window_slots, deposit_cap, deposit_window_slots, withdrawal_cap, withdrawal_window_slots] =
            bytemuck::cast::<_, [[u8; 8]; 8]>(bytes).map(u64::from_be_bytes);
        Self {
            sender_cap,
            sender_window_slots,
            volume_cap,
            volume_window_slots,
            deposit_cap,
            deposit_window_slots,
            withdrawal_cap,
            withdrawal_window_slots,
        }
    }

    pub fn bytes(self) -> [u8; Self::LEN] {
        bytemuck::cast(
            [
                self.sender_cap,
                self.sender_window_slots,
                self.volume_cap,
                self.volume_window_slots,
                self.deposit_cap,
                self.deposit_window_slots,
                self.withdrawal_cap,
                self.withdrawal_window_slots,
            ]
            .map(u64::to_be_bytes),
        )
    }

    /// Zero disables a cap, each cap and its window are both zero or both nonzero.
    pub const fn check(self) -> Result<Self, AssetLimitsError> {
        const fn paired(cap: u64, window_slots: u64) -> bool {
            (cap == 0) == (window_slots == 0)
        }
        if paired(self.sender_cap, self.sender_window_slots)
            && paired(self.volume_cap, self.volume_window_slots)
            && paired(self.deposit_cap, self.deposit_window_slots)
            && paired(self.withdrawal_cap, self.withdrawal_window_slots)
        {
            Ok(self)
        } else {
            Err(AssetLimitsError::UnpairedWindow)
        }
    }

    pub fn fields(self) -> [[u8; 32]; Self::FIELDS] {
        let mut fields = [[0; 32]; Self::FIELDS];
        for (field, amounts) in fields
            .iter_mut()
            .zip(self.bytes().chunks(FIELD_AMOUNT_BYTES))
        {
            field[32 - amounts.len()..].copy_from_slice(amounts);
        }
        fields
    }
}
