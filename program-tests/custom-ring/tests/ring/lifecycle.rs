use super::*;

#[test]
fn localnet_bring_up_is_live() -> Result<()> {
    let env = setup()?;
    let rpc = env.client.rpc();

    // 1. Every program the lifecycle CPIs into is deployed and executable. A
    //    missing `just build-programs` shows up here rather than as an opaque
    //    "program account not found" mid-flow.
    let ring_program = custom_ring_program_id()?;
    for (label, program) in [
        ("custom-ring", ring_program),
        (
            "shielded-pool",
            Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        ),
        ("user-registry", user_registry_program_id()),
        ("smart-account", smart_account::SMART_ACCOUNT_PROGRAM_ID),
    ] {
        rpc.assert_executable(&program)
            .with_context(|| format!("{label} program {program}"))?;
    }

    // 2. The protocol config carries exactly the bootstrap settings the ring
    //    flows depend on, `ring_activation_is_permissionless` above all: without
    //    it the custom-ring program cannot register its `ring_auth` PDA as an
    //    SPP ring config with a plain payer.
    let accounts = smart_account::standard_accounts();
    let config: ProtocolConfig = fetch_state(rpc, &pda::protocol_config())?;
    assert_eq!(
        config,
        ProtocolConfig {
            discriminator: PROTOCOL_CONFIG,
            protocol_authority: accounts.protocol_vault,
            fee_authority: accounts.protocol_vault,
            tree_creation_authority: accounts.tree_vault,
            forester_authority: accounts.forester_vault,
            ring_creation_authority: accounts.ring_vault,
            tree_creation_is_permissionless: 0,
            ring_activation_is_permissionless: 1,
            spl_interface_creation_is_permissionless: 0,
            next_tree_id: 1,
        },
        "protocol config"
    );

    // 3. The registry the wallets share resolves SOL and the bring-up's USDC
    //    mint, and the USDC interface vault exists empty beside the counter.
    assert_eq!(
        env.assets
            .resolve(SOL_ASSET_ID)
            .map_err(|e| anyhow!("SOL asset resolution failed {e:?}"))?
            .asset,
        SOL_MINT,
        "asset id 1 is SOL"
    );
    assert_eq!(
        env.assets
            .resolve(USDC_ASSET_ID)
            .map_err(|e| anyhow!("USDC asset resolution failed {e:?}"))?
            .asset,
        env.usdc_mint,
        "the bring-up USDC mint sits at the first allocated id"
    );
    fetch_account(rpc, &pda::spl_asset_counter())?;
    assert_eq!(
        token_amount(&fetch_account(rpc, &pda::spl_interface(&env.usdc_mint))?),
        0,
        "USDC interface vault starts empty"
    );

    // 4. The default tree is owned by SPP, exactly account-sized, and parses
    //    through the canonical layout with a rooted, unpaused state tree.
    let tree_account = rpc
        .get_account(env.tree)?
        .ok_or_else(|| anyhow!("tree account {} not found", env.tree))?;
    assert_eq!(
        tree_account.owner,
        Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        "tree owner"
    );
    assert_eq!(tree_account.data.len(), tree_account_size(), "tree size");
    let mut tree_bytes = tree_account.data.clone();
    let tree = TreeAccount::from_bytes(&mut tree_bytes, env.tree.to_bytes())
        .map_err(|e| anyhow!("tree layout failed {e:?}"))?;
    assert_eq!(
        tree.discriminator(),
        TREE_ACCOUNT_DISCRIMINATOR,
        "tree discriminator"
    );
    assert!(!tree.is_paused(), "tree must be unpaused after creation");
    let state_root = tree
        .get_utxo_tree_root(0)
        .map_err(|e| anyhow!("UTXO tree root failed {e:?}"))?;
    assert_ne!(state_root, [0u8; 32], "empty state tree still has a root");

    // 5. Photon answers the tag query the auditor client pages through, and has
    //    persisted at least one slot of the chain it is indexing.
    let indexed = env
        .client
        .indexer()
        .get_shielded_transactions_by_tags(vec![UNUSED_VIEW_TAG], None, Some(10), None)
        .map_err(|e| anyhow!("indexer {} failed {e:?}", env.indexer_url))?;
    assert!(
        indexed.transactions.is_empty(),
        "no transaction exists under the unused probe tag"
    );
    assert!(indexed.context.slot > 0, "indexer has persisted a slot");

    // 6. The prover listener the client will POST to is the one that came up.
    //    `spawn_workspace_prover` already ran the HTTP health probe; this pins
    //    that the resolved URL (per-clone `ZOLANA_PROVER_URL`) is reachable.
    let prover = prover_url();
    let host_port = prover
        .rsplit("//")
        .next()
        .map(|rest| rest.trim_end_matches('/'))
        .ok_or_else(|| anyhow!("prover url {prover} has no host"))?;
    let socket = host_port
        .to_socket_addrs()
        .with_context(|| format!("resolve prover {prover}"))?
        .next()
        .ok_or_else(|| anyhow!("prover url {prover} resolves to no address"))?;
    TcpStream::connect_timeout(&socket, Duration::from_secs(5))
        .with_context(|| format!("connect to prover {prover}"))?;

    // 7+8. Both send paths the lifecycle uses work on this validator: the
    //      harness helper and the client's compile and sign path that a ring
    //      submission takes. Both build transaction v1 messages, whose
    //      4096-byte limit is what a ring transact needs; this validator must
    //      accept the format at all. Each probe is asserted by its lamport
    //      effect.
    let sender = env.sender.keypair.pubkey();
    let recipient = env.recipient.keypair.pubkey();
    let sender_before = lamports(rpc, sender)?;
    let recipient_before = lamports(rpc, recipient)?;

    send(
        rpc,
        &env.payer,
        &[solana_system_interface::instruction::transfer(
            &env.payer.pubkey(),
            &sender,
            PROBE_TRANSFER,
        )],
    )?;
    assert_eq!(
        lamports(rpc, sender)?,
        sender_before + PROBE_TRANSFER,
        "harness v1 transfer credited the sender"
    );

    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = compile_message(
        &env.payer.pubkey(),
        &[solana_system_interface::instruction::transfer(
            &env.payer.pubkey(),
            &recipient,
            PROBE_TRANSFER,
        )],
        blockhash,
        ComputeBudgetConfig::for_instruction_count(1),
    )?;
    rpc.process_transaction(sign_transaction(message, &[&env.payer])?)?;
    assert_eq!(
        lamports(rpc, recipient)?,
        recipient_before + PROBE_TRANSFER,
        "client v1 transfer credited the recipient"
    );

    Ok(())
}

/// The ring rpc reads the Loader v3 upgrade authority and the config authority
/// from the chain, so this runs against the deployed program, not a mock.
#[test]
fn auditor_key_is_released_only_to_the_ring_authority() -> Result<()> {
    let env = setup()?;
    let rpc = env.client.rpc();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let runtime = tokio::runtime::Runtime::new()?;
    let source = ChainSource::connect(Upstreams {
        indexer_url: &env.indexer_url,
        rpc_url: &env.rpc_url,
        timeout: Duration::from_secs(30),
    })
    .map_err(|e| anyhow!("ring rpc upstreams {e:?}"))?;
    let genesis_hash = runtime
        .block_on(source.genesis_hash())
        .map_err(|e| anyhow!("genesis hash {e:?}"))?;
    let hub = Hub::builder(source, genesis_hash)
        .derived(RootSecret::from_bytes([7; 32])?)
        .map_err(|e| anyhow!("hub {e:?}"))?;
    let service = hub
        .service(Some(ring_program))
        .map_err(|e| anyhow!("service {e:?}"))?;
    let request = |authority: &Keypair, genesis: [u8; 32]| {
        CreateAuditorKeyRequest::for_ring(ring_program, genesis).sign(authority)
    };
    let authorize = |request: &CreateAuditorKeyRequest| {
        runtime
            .block_on(service.auditor_key_statement(&request.auth))
            .map(drop)
    };
    let expect_refusal = |result: Result<(), RingRpcError>, expected: Unauthorized| match result {
        Err(RingRpcError::Unauthorized(reason)) if reason == expected => Ok(()),
        other => Err(anyhow!("expected {expected:?}, got {other:?}")),
    };
    let stranger = Keypair::new();
    let config_authority = Keypair::new();

    // 1. No config yet, so only the program's upgrade authority is accepted.
    expect_refusal(
        authorize(&request(&stranger, genesis_hash)?),
        Unauthorized::NotRingAuthority,
    )?;
    expect_refusal(
        authorize(&request(&config_authority, genesis_hash)?),
        Unauthorized::NotRingAuthority,
    )?;
    expect_refusal(
        authorize(&request(&env.payer, [0; 32])?),
        Unauthorized::ClusterMismatch,
    )?;
    let released = request(&env.payer, genesis_hash)?;
    authorize(&released).map_err(|e| anyhow!("upgrade authority {e:?}"))?;
    expect_refusal(authorize(&released), Unauthorized::Replay)?;

    // 2. Once the config exists its authority alone is accepted, even after
    //    the deployer hands it over.
    rpc.create_and_send_transaction(
        &[
            custom_ring_sdk::Initialize {
                ring,
                payer: env.payer.pubkey(),
                authority: env.payer.pubkey(),
                auditor_pubkey: service.auditor_pubkey(),
                kind: custom_ring_sdk::RingKind::AuditOnly,
                policy: None,
            }
            .instruction()?,
            custom_ring_sdk::UpdateAuthority {
                ring,
                authority: env.payer.pubkey(),
                new_authority: config_authority.pubkey(),
            }
            .instruction(),
        ],
        env.payer.pubkey(),
        &[&env.payer, &config_authority],
        ComputeBudgetConfig::for_instruction_count(2),
    )?;
    authorize(&request(&config_authority, genesis_hash)?)
        .map_err(|e| anyhow!("config authority {e:?}"))?;
    for refused in [&env.payer, &stranger] {
        expect_refusal(
            authorize(&request(refused, genesis_hash)?),
            Unauthorized::NotRingAuthority,
        )?;
    }
    Ok(())
}

/// The operator cli against the deployed program, the config authority is a
/// second key and the rerun sees the config through a hosted-looking ring rpc.
#[test]
fn cli_init_hands_the_config_over_and_reruns_from_the_chain() -> Result<()> {
    let env = setup()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    let auditor = X25519Keypair::new();
    let project = RingProject::create(&env, &auditor.pubkey())?;
    let init = || project.run(&["init"]);

    // 1. A local ring rpc lets the key file through, the config is created
    //    under the deployer and handed over in the same run.
    project.write_config(RingToml {
        env: &env,
        ring_rpc: "http://127.0.0.1:1",
        policy: None,
        mode: ModeName::Confidential,
    })?;
    let first = init()?;
    assert!(first.contains("authority   transferred"), "{first}");
    let config = env
        .run(ring.config(env.client.as_async()))?
        .ok_or_else(|| anyhow!("config after init"))?;
    assert_eq!(config.authority, project.config_authority.pubkey());
    assert_eq!(config.auditor_pubkey, auditor.pubkey());

    // 2. The rerun takes the key from the chain, so the hosted-looking rpc is
    //    never asked and the key file is not mistaken for a local key.
    project.write_config(RingToml {
        env: &env,
        ring_rpc: "http://ring.invalid:1",
        policy: None,
        mode: ModeName::Confidential,
    })?;
    let second = init()?;
    assert!(second.contains("config      already present"), "{second}");
    assert!(second.contains("authority   already present"), "{second}");

    // 3. The config authority closes and reopens the ring through the program,
    //    the SPP flag follows each run.
    let paused = project.run(&["authority", "pause"])?;
    assert!(paused.contains("spp ring    paused"), "{paused}");
    assert!(registration(&env, ring)?.paused, "paused by the cli");
    let resumed = project.run(&["authority", "resume"])?;
    assert!(resumed.contains("spp ring    resumed"), "{resumed}");
    assert!(!registration(&env, ring)?.paused, "reopened by the cli");
    project.remove()?;
    Ok(())
}
