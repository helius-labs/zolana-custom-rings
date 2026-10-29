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

impl AssetLimits {
    pub const LEN: usize = 48;

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
}
