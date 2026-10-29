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
    pub withdrawal_cap: u64,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AssetLimitsError {
    #[error("a window cap and its window are not set together")]
    UnpairedWindow,
}

impl AssetLimits {
    pub const LEN: usize = 48;

    pub const EMPTY: Self = Self {
        sender_cap: 0,
        sender_window_slots: 0,
        volume_cap: 0,
        volume_window_slots: 0,
        deposit_cap: 0,
        withdrawal_cap: 0,
    };

    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        let [sender_cap, sender_window_slots, volume_cap, volume_window_slots, deposit_cap, withdrawal_cap] =
            bytemuck::cast::<_, [[u8; 8]; 6]>(bytes).map(u64::from_be_bytes);
        Self {
            sender_cap,
            sender_window_slots,
            volume_cap,
            volume_window_slots,
            deposit_cap,
            withdrawal_cap,
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
                self.withdrawal_cap,
            ]
            .map(u64::to_be_bytes),
        )
    }

    /// Zero disables a cap, a window cap and its window are both zero or both nonzero.
    pub const fn check(self) -> Result<Self, AssetLimitsError> {
        if (self.sender_cap == 0) != (self.sender_window_slots == 0)
            || (self.volume_cap == 0) != (self.volume_window_slots == 0)
        {
            return Err(AssetLimitsError::UnpairedWindow);
        }
        Ok(self)
    }

    /// Three amounts per field, each field below 2^192.
    pub fn fields(self) -> [[u8; 32]; 2] {
        bytemuck::cast::<_, [[u8; 24]; 2]>(self.bytes()).map(|amounts| {
            let mut field = [0; 32];
            field[8..].copy_from_slice(&amounts);
            field
        })
    }
}
