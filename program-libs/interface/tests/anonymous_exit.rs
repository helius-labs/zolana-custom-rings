use custom_ring_interface::{
    AnonymousExitDestination, AnonymousParties, CustomRingError, SettlementAccount,
    TokenAccountControl, TokenAccountState, SYSTEM_PROGRAM_ID,
};
use solana_address::Address;
use spl_token_2022_interface::pod::{PodAccount, PodCOption};
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::{
    instruction::InterfaceTransfer, SPL_TOKEN_ACCOUNT_INITIALIZED, SPL_TOKEN_ACCOUNT_LEN,
    SPL_TOKEN_PROGRAM_ID,
};

const MINT: [u8; 32] = [1; 32];
const OWNER: [u8; 32] = [2; 32];
const OFF_CURVE: Address = Address::new_from_array([0x44; 32]);
const ON_CURVE: Address = Address::new_from_array([0x55; 32]);

fn token_account(edit: impl FnOnce(&mut PodAccount)) -> Vec<u8> {
    let mut state = PodAccount {
        mint: MINT.into(),
        owner: OWNER.into(),
        state: SPL_TOKEN_ACCOUNT_INITIALIZED,
        ..PodAccount::default()
    };
    edit(&mut state);
    bytemuck::bytes_of(&state).to_vec()
}

struct Account {
    address: Address,
    owner: Address,
    data: Vec<u8>,
}

impl SettlementAccount for Account {
    fn address(&self) -> &Address {
        &self.address
    }

    fn owner(&self) -> &Address {
        &self.owner
    }

    fn token_account(&self) -> Result<TokenAccountState, CustomRingError> {
        TokenAccountState::unpack(&self.data)
    }
}

fn filler() -> Account {
    Account {
        address: Address::new_from_array([9; 32]),
        owner: SYSTEM_PROGRAM_ID,
        data: vec![],
    }
}

fn sol_group(recipient: Address, data: Vec<u8>) -> Vec<Account> {
    vec![
        filler(),
        Account {
            address: recipient,
            owner: SYSTEM_PROGRAM_ID,
            data,
        },
    ]
}

fn spl_group(token_account_address: Address, data: Vec<u8>) -> Vec<Account> {
    vec![
        filler(),
        filler(),
        filler(),
        Account {
            address: token_account_address,
            owner: Address::new_from_array(SPL_TOKEN_PROGRAM_ID),
            data,
        },
        filler(),
    ]
}

#[test]
fn a_second_authority_shares_control_of_the_account() {
    let unpacked = |edit: fn(&mut PodAccount)| TokenAccountState::unpack(&token_account(edit));
    assert_eq!(
        unpacked(|_| {}),
        Ok(TokenAccountState {
            mint: MINT,
            control: TokenAccountControl::SoleOwner(OWNER),
        })
    );
    for edit in [
        (|state| state.delegate = PodCOption::some([3; 32].into())) as fn(&mut PodAccount),
        |state| state.close_authority = PodCOption::some([3; 32].into()),
    ] {
        assert_eq!(
            unpacked(edit).map(|state| state.control),
            Ok(TokenAccountControl::Shared(OWNER))
        );
    }
}

#[test]
fn an_account_reads_only_in_the_layouts_the_token_programs_write() {
    let base = token_account(|_| {});
    let mut extended = base.clone();
    extended.extend_from_slice(&[2, 0, 0, 0, 0]);
    assert!(TokenAccountState::unpack(&extended).is_ok());
    let mut mint_typed = extended.clone();
    mint_typed[SPL_TOKEN_ACCOUNT_LEN] = 1;
    let mut multisig = base.clone();
    multisig.resize(355, 0);
    let frozen = token_account(|state| state.state = 2);
    for refused in [&base[..164], &mint_typed, &multisig, &frozen] {
        assert_eq!(
            TokenAccountState::unpack(refused),
            Err(CustomRingError::AnonymousExitTokenAccountInvalid)
        );
    }
}

#[test]
fn an_anonymous_exit_names_one_key_or_its_refusal() {
    assert!(!OFF_CURVE.is_on_curve() && ON_CURVE.is_on_curve());
    let (sole, shared) = (
        TokenAccountControl::SoleOwner(OWNER),
        TokenAccountControl::Shared(OWNER),
    );
    let wallet = Address::new_from_array([5; 32]);
    let token_program = Address::new_from_array(SPL_TOKEN_PROGRAM_ID);
    let sol = |owner, data_len| AnonymousExitDestination::Sol {
        recipient: &wallet,
        owner,
        data_len,
    };
    let spl = |token_account, control| AnonymousExitDestination::Spl {
        token_account,
        control,
    };
    for (exit, named) in [
        (sol(&SYSTEM_PROGRAM_ID, 0), Ok([5; 32])),
        (spl(&OFF_CURVE, &sole), Ok(OWNER)),
        (
            sol(&SYSTEM_PROGRAM_ID, 80),
            Err(CustomRingError::AnonymousExitAccountHasData),
        ),
        (
            sol(&token_program, 0),
            Err(CustomRingError::AnonymousExitAccountHasData),
        ),
        (
            spl(&ON_CURVE, &sole),
            Err(CustomRingError::AnonymousExitTokenAccountOnCurve),
        ),
        (
            spl(&OFF_CURVE, &shared),
            Err(CustomRingError::AnonymousExitTokenAccountShared),
        ),
    ] {
        assert_eq!(exit.named_key().copied(), named, "{exit:?}");
    }
}

/// The payer, the funders and the exit take no cell.
#[test]
fn the_co_signers_fill_the_cells_in_order() {
    let co_signers = [
        Address::new_from_array([8; 32]),
        Address::new_from_array([9; 32]),
    ];
    let parties = AnonymousParties {
        co_signers: &co_signers,
    };
    assert_eq!(
        parties.identities(),
        Ok([
            solana_owner_identity(co_signers[0].as_array()).unwrap(),
            solana_owner_identity(co_signers[1].as_array()).unwrap(),
            [0; 32],
            [0; 32],
            [0; 32],
        ])
    );
}

#[test]
fn a_co_signer_past_the_fifth_is_refused() {
    let co_signers = [Address::new_from_array([8; 32]); 6];
    assert!(AnonymousParties {
        co_signers: &co_signers[..5],
    }
    .identities()
    .is_ok());
    assert_eq!(
        AnonymousParties {
            co_signers: &co_signers,
        }
        .identities(),
        Err(CustomRingError::TooManyAnonymousParties)
    );
}

#[test]
fn policy_withdrawals_authenticate_live_owners_and_preserve_order() {
    use custom_ring_interface::{policy_withdrawal_hash, policy_withdrawals, PolicyWithdrawal};
    let spl = InterfaceTransfer::SplWithdrawal {
        amount: 9,
        spl_interface_bump: 0,
    };
    let sol = InterfaceTransfer::SolWithdrawal { amount: 7 };
    let mut group = spl_group(
        ON_CURVE,
        token_account(|state| {
            // Ordinary policy payments may use shared accounts; screening names the actual owner.
            state.delegate = PodCOption::some([3; 32].into());
        }),
    );
    group[spl.mint_account_position().unwrap()].address = Address::new_from_array(MINT);
    let mut accounts = sol_group(Address::new_from_array(OWNER), vec![]);
    accounts.extend(group);
    let legs = policy_withdrawals(&[sol, spl], &accounts, &[OWNER]).unwrap();
    assert_eq!(
        legs,
        [
            PolicyWithdrawal::new(&OWNER, None, 7).unwrap(),
            PolicyWithdrawal::new(&OWNER, Some(&MINT), 9).unwrap()
        ]
    );
    let hash = policy_withdrawal_hash(&legs).unwrap();
    assert_ne!(hash, policy_withdrawal_hash(&[legs[1], legs[0]]).unwrap());
    assert_ne!(hash, policy_withdrawal_hash(&legs[..1]).unwrap());
    for owners in [vec![], vec![[8; 32]], vec![OWNER, OWNER]] {
        assert!(policy_withdrawals(&[sol, spl], &accounts, &owners).is_err());
    }
    assert!(policy_withdrawals(&[spl, sol], &accounts, &[OWNER]).is_err());
    // Account ownership changing between preparation and execution invalidates the metadata.
    accounts[5].data = token_account(|state| state.owner = [8; 32].into());
    assert!(policy_withdrawals(&[sol, spl], &accounts, &[OWNER]).is_err());
    accounts[5].data = token_account(|state| state.mint = [8; 32].into());
    assert!(policy_withdrawals(&[sol, spl], &accounts, &[OWNER]).is_err());
    accounts[5].data = token_account(|state| state.state = 0);
    assert!(policy_withdrawals(&[sol, spl], &accounts, &[OWNER]).is_err());
    accounts[5].data.clear();
    assert!(policy_withdrawals(&[sol, spl], &accounts, &[OWNER]).is_err());
    accounts[5].data = token_account(|_| {});
    accounts[5].owner = SYSTEM_PROGRAM_ID;
    assert!(policy_withdrawals(&[sol, spl], &accounts, &[OWNER]).is_err());
}

/// The ring circuit range checks no leg, the program's digest over u64 settlement amounts bounds each.
#[test]
fn withdrawal_digest_reads_u64_settlement_amounts() {
    use custom_ring_interface::{domain, policy_withdrawal_hash, policy_withdrawals};
    use spr_hasher::{hash_chain::create_hash_chain_4, primitives::right_align};
    let settled = InterfaceTransfer::SolWithdrawal { amount: u64::MAX };
    let accounts = sol_group(Address::new_from_array(OWNER), vec![]);
    let legs = policy_withdrawals(&[settled], &accounts, &[]).unwrap();
    assert_eq!(legs[0].amount, u64::MAX);
    // The amount field is the u64 right aligned, its 24 high bytes stay zero for every settlement.
    let amount = right_align(&u64::MAX.to_be_bytes());
    assert_eq!(amount[..24], [0; 24]);
    let fields = [
        domain::field(domain::WITHDRAWALS),
        right_align(&1u64.to_be_bytes()),
        legs[0].owner,
        legs[0].asset,
        amount,
    ];
    assert_eq!(
        policy_withdrawal_hash(&legs).unwrap(),
        create_hash_chain_4(fields.iter()).unwrap()
    );
}

#[test]
fn repeated_owners_and_mints_screen_as_their_first_leg() {
    use custom_ring_interface::{policy_withdrawals, PolicyWithdrawal};
    let spl = InterfaceTransfer::SplWithdrawal {
        amount: 9,
        spl_interface_bump: 0,
    };
    let sol = InterfaceTransfer::SolWithdrawal { amount: 7 };
    let mut accounts = sol_group(Address::new_from_array(OWNER), vec![]);
    accounts.extend(sol_group(Address::new_from_array(OWNER), vec![]));
    for _ in 0..2 {
        let mut group = spl_group(ON_CURVE, token_account(|_| {}));
        group[spl.mint_account_position().unwrap()].address = Address::new_from_array(MINT);
        accounts.extend(group);
    }
    let legs = policy_withdrawals(&[sol, sol, spl, spl], &accounts, &[OWNER, OWNER]).unwrap();
    assert_eq!(
        legs,
        [
            PolicyWithdrawal::new(&OWNER, None, 7).unwrap(),
            PolicyWithdrawal::new(&OWNER, None, 7).unwrap(),
            PolicyWithdrawal::new(&OWNER, Some(&MINT), 9).unwrap(),
            PolicyWithdrawal::new(&OWNER, Some(&MINT), 9).unwrap(),
        ]
    );
}

#[test]
fn policy_deposits_are_not_screened_and_zero_withdrawals_are_refused() {
    use custom_ring_interface::policy_withdrawals;
    let deposits = [
        InterfaceTransfer::SolDeposit { amount: 8 },
        InterfaceTransfer::SplDeposit {
            amount: 9,
            spl_interface_bump: 0,
        },
    ];
    let groups: Vec<_> = deposits
        .iter()
        .flat_map(|leg| (0..leg.settlement_account_count()).map(|_| filler()))
        .collect();
    assert_eq!(policy_withdrawals(&deposits, &groups, &[]).unwrap(), []);
    assert!(policy_withdrawals(
        &[InterfaceTransfer::SolWithdrawal { amount: 0 }],
        &sol_group(ON_CURVE, vec![]),
        &[]
    )
    .is_err());
}
