use custom_ring_interface::{
    anonymous_exit_destination, AnonymousExitDestination, AnonymousParties, CustomRingError,
    SettlementAccount, TokenAccountControl, TokenAccountState, SYSTEM_PROGRAM_ID,
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

    fn data_len(&self) -> usize {
        self.data.len()
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

#[test]
fn every_withdrawal_of_a_spend_names_the_same_destination() {
    let sol_out = InterfaceTransfer::SolWithdrawal { amount: 1 };
    let sol_in = InterfaceTransfer::SolDeposit { amount: 1 };
    let spl_out = InterfaceTransfer::SplWithdrawal {
        amount: 1,
        spl_interface_bump: 0,
    };
    let wallet = Address::new_from_array(OWNER);
    let window = |groups: Vec<Vec<Account>>| groups.into_iter().flatten().collect::<Vec<_>>();

    assert_eq!(
        anonymous_exit_destination(&[sol_in], &window(vec![sol_group(wallet, vec![])])),
        Ok(None)
    );
    assert_eq!(
        anonymous_exit_destination(
            &[sol_out, spl_out],
            &window(vec![
                sol_group(wallet, vec![]),
                spl_group(OFF_CURVE, token_account(|_| {})),
            ])
        ),
        Ok(Some(OWNER))
    );
    assert_eq!(
        anonymous_exit_destination(
            &[sol_out, sol_out],
            &window(vec![
                sol_group(wallet, vec![]),
                sol_group(Address::new_from_array([6; 32]), vec![]),
            ])
        ),
        Err(CustomRingError::AnonymousExitDestinationsDiffer)
    );
    let mut foreign = spl_group(OFF_CURVE, token_account(|_| {}));
    foreign[3].owner = SYSTEM_PROGRAM_ID;
    assert_eq!(
        anonymous_exit_destination(&[spl_out], &foreign),
        Err(CustomRingError::AnonymousExitTokenAccountInvalid)
    );
    assert_eq!(
        anonymous_exit_destination(&[spl_out], &sol_group(wallet, vec![])),
        Err(CustomRingError::InvalidSettlementAccounts)
    );
}

#[test]
fn an_absent_party_is_a_zero_identity() {
    let payer = [7; 32];
    let parties = AnonymousParties {
        payer: &payer,
        cosigner: None,
        exit_destination: Some(&OWNER),
    };
    assert_eq!(
        parties.identities(),
        Ok([
            solana_owner_identity(&payer).unwrap(),
            [0; 32],
            solana_owner_identity(&OWNER).unwrap(),
        ])
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
