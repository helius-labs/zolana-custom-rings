//! The allocator position after the handler is the peak.

use pinocchio::{entrypoint::HEAP_START_ADDRESS, AccountView, Address, ProgramResult};

pinocchio::entrypoint!(process_instruction);

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let result = custom_ring_program::process_instruction(program_id, accounts, data);
    // SAFETY: the heap's first word holds the allocator position.
    let position = unsafe { *(HEAP_START_ADDRESS as *const u64) };
    let peak = position.saturating_sub(HEAP_START_ADDRESS).to_le_bytes();
    pinocchio::cpi::set_return_data(&peak);
    result
}
