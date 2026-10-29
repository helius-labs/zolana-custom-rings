//! Loaded ring context and transaction landing.

use super::*;

/// Slots a signed record update stays acceptable to the writer.
const RECORD_UPDATE_SLOTS: u64 = 150;

pub struct Context {
    pub config_path: PathBuf,
    /// The directory of ring.toml, relative key paths resolve against it.
    pub root: PathBuf,
    pub config: RingConfig,
    pub ring: CustomRing,
    pub zolana: Zolana,
    /// The `--catalogue` override, `None` for the bundled file.
    pub catalogue: Option<String>,
    ask: RefCell<Box<dyn Ask>>,
    authority: OnceCell<Keypair>,
    fee_payer_keypair: Option<PathBuf>,
    fee_payer: OnceCell<Keypair>,
}

#[must_use]
pub struct ContextSetup {
    pub config_path: PathBuf,
    pub config: RingConfig,
    pub ask: Box<dyn Ask>,
    pub catalogue: Option<String>,
    pub prover_tee_policy: Option<TeePolicy>,
    pub fee_payer_keypair: Option<PathBuf>,
}

pub enum Probe<T> {
    Ready(T),
    NotYet,
    Retry(anyhow::Error),
}

#[must_use]
pub struct Landing<'a> {
    pub operation: RingOperation<'a>,
    pub payer: &'a (dyn Signer + Sync),
    pub signers: &'a [&'a (dyn Signer + Sync)],
}

impl ContextSetup {
    pub fn open(self) -> Result<Context> {
        let ContextSetup {
            config_path,
            mut config,
            ask,
            catalogue,
            prover_tee_policy,
            fee_payer_keypair,
        } = self;
        let root = config_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        config.resolve_keypair_paths(|path| resolve(&root, path));
        let urls = config.urls();
        let zolana = ZolanaServices {
            rpc: SolanaRpc::new(urls.rpc.clone()),
            indexer: ZolanaIndexer::new(&urls.indexer),
            prover: urls.prover_client(&root, prover_tee_policy.clone())?,
            ring_prover: urls.prover_client(&root, prover_tee_policy)?,
        }
        .connect();
        Ok(Context {
            ring: CustomRing::new(config.program_id.0),
            config_path,
            root,
            config,
            zolana,
            catalogue,
            ask: RefCell::new(ask),
            authority: OnceCell::new(),
            fee_payer_keypair,
            fee_payer: OnceCell::new(),
        })
    }
}

impl Landing<'_> {
    /// Resent until the cluster settles it, a stale root is proved again.
    pub fn settle(self, zolana: &Zolana) -> Result<Signature> {
        let mut submission = RingSubmission::new(self.operation);
        let settled = zolana.block_on(submission.send_until_settled(
            zolana.ring_client(),
            self.payer,
            self.signers,
        ))?;
        match settled {
            SettledSubmission::Confirmed { signature, .. } => Ok(signature),
            SettledSubmission::Failed { signature, error } => {
                Err(RingError::Rejected { signature, error }.into())
            }
        }
    }
}

impl Context {
    /// Relative to the ring directory, an absolute or `~` path as given.
    pub fn path(&self, path: &Path) -> PathBuf {
        resolve(&self.root, path)
    }

    pub fn rpc(&self) -> &SolanaRpc {
        self.zolana.rpc()
    }

    pub fn chain(&self) -> &Chain {
        self.zolana.as_async()
    }

    pub fn ring_client(
        &self,
    ) -> &custom_ring_sdk::RingClient<Blocking<SolanaRpc>, Blocking<ZolanaIndexer>> {
        self.zolana.ring_client()
    }

    pub fn block<T, E: From<BlockingInsideRuntime>>(
        &self,
        future: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        self.zolana.block_on(future)
    }

    pub fn ring_config(&self) -> Result<CustomRingConfig> {
        self.block(self.ring.config(self.chain()))?
            .context("the ring has no config, run `zolana-ring init` first")
    }

    /// The config authority, read once.
    pub fn authority(&self) -> Result<&Keypair> {
        if let Some(authority) = self.authority.get() {
            return Ok(authority);
        }
        let authority = self.config.config_authority()?;
        Ok(self.authority.get_or_init(|| authority))
    }

    /// An anonymous ring's member operations take `--fee-payer-keypair`, apart from the hidden owner.
    pub(crate) fn member_payer(&self, mode: RingMode, owner: Address) -> Result<&Keypair> {
        if mode != RingMode::Anonymous {
            return self.authority();
        }
        let payer = match self.fee_payer.get() {
            Some(payer) => payer,
            None => {
                let path = self.fee_payer_keypair.as_deref().context(
                    "an anonymous ring pays its member operations from --fee-payer-keypair, a key apart from the hidden owner",
                )?;
                let payer = file::read_keypair(&self.path(path))?;
                self.fee_payer.get_or_init(|| payer)
            }
        };
        ensure!(
            payer.pubkey() != owner,
            "the fee payer {owner} is the hidden owner, paying would publish it"
        );
        Ok(payer)
    }

    /// For a step that only pays fees and small rent.
    pub fn funded_authority(&self) -> Result<&Keypair> {
        let authority = self.authority()?;
        self.fund(authority.pubkey(), fund::MIN_AUTHORITY_BALANCE)?;
        Ok(authority)
    }

    /// Localnet airdrops what the step spends, devnet waits at the faucet.
    pub fn fund(&self, who: Address, required: u64) -> Result<()> {
        match self.config.target {
            Target::Localnet => {
                if self.rpc().get_balance(who)? < required.max(LOCALNET_BALANCE / 2) {
                    SolanaRpc::new(self.config.urls().rpc.clone())
                        .airdrop(&who, required.max(LOCALNET_BALANCE))?;
                }
                Ok(())
            }
            Target::Devnet => {
                fund::wait_for_balance(self.rpc(), &mut **self.ask.borrow_mut(), who, required)
            }
        }
    }

    /// No airdrop, for a step that must not move the operator's funds itself.
    pub fn require_balance(&self, who: Address, required: u64) -> Result<()> {
        let balance = self.rpc().get_balance(who)?;
        ensure!(
            balance >= required,
            "{who} holds {balance} lamports, {required} are needed"
        );
        Ok(())
    }

    /// Kept between runs, earlier change stays spendable with it.
    pub fn sender(&self) -> Result<Keypair> {
        file::read_or_create_keypair(&self.path(Path::new(SENDER_KEYPAIR_FILE)))
    }

    /// `signers[0]` pays, each ring instruction brings its own compute budget.
    pub fn send(&self, signers: &[&dyn Signer], instructions: &[Instruction]) -> Result<Signature> {
        let payer = signers.first().context("a transaction needs a payer")?;
        let units = instructions
            .iter()
            .map(|instruction| self.compute_units(instruction))
            .fold(0u32, u32::saturating_add)
            .min(MAX_COMPUTE_UNITS);
        self.rpc()
            .create_and_send_transaction(
                instructions,
                payer.pubkey(),
                signers,
                ComputeBudgetConfig::new(units),
            )
            .map_err(|error| match hint(&error) {
                Some(hint) => anyhow::Error::new(error).context(hint),
                None => error.into(),
            })
    }

    pub fn submit<'a>(
        &self,
        operation: impl Into<RingOperation<'a>>,
        payer: &(dyn Signer + Sync),
        signers: &[&(dyn Signer + Sync)],
    ) -> Result<Signature> {
        Landing {
            operation: operation.into(),
            payer,
            signers,
        }
        .settle(&self.zolana)
    }

    pub fn wait_for_indexed(&self, signature: Signature) -> Result<()> {
        wait_for_indexed_transaction(&self.zolana, signature)
    }

    pub fn interactive(&self) -> bool {
        self.ask.borrow().interactive()
    }

    pub fn ask_yes(&self, prompt: &str, default: bool) -> Result<bool> {
        self.ask.borrow_mut().confirm(prompt, default)
    }

    /// `--yes` skips the question, without a terminal `needs_yes` is the error.
    pub fn confirm(
        &self,
        yes: bool,
        prompt: &str,
        needs_yes: impl Display,
        declined: impl Display,
    ) -> Result<()> {
        if yes {
            return Ok(());
        }
        ensure!(self.interactive(), "{needs_yes}");
        ensure!(self.ask_yes(prompt, false)?, "{declined}");
        Ok(())
    }

    pub fn ring_rpc(&self) -> RingRpcClient {
        RingRpcClient::new(&self.config.urls().ring_rpc)
    }

    pub fn record_update_target(&self) -> Result<custom_ring_sdk::RecordUpdateTarget> {
        let policy = self
            .block(
                self.ring
                    .read::<custom_ring_interface::RingPolicy>(self.chain()),
            )?
            .context("the ring has no policy account, run `zolana-ring init` first")?;
        Ok(custom_ring_sdk::RecordUpdateTarget {
            genesis_hash: self.rpc().genesis_hash()?,
            ring: self.ring,
            registry: policy.records,
            valid_until_slot: self.rpc().get_slot()?.saturating_add(RECORD_UPDATE_SLOTS),
        })
    }

    /// `unpinned` applies only when ring.toml pins no service key.
    pub fn trust(&self, unpinned: Trust) -> Result<Trust> {
        match self.config.urls().ring_rpc_pubkey.as_deref() {
            Some(key) => key
                .parse()
                .map(Trust::Pinned)
                .with_context(|| format!("ring_rpc_pubkey {key} is not a base58 key")),
            None => Ok(unpinned),
        }
    }

    fn compute_units(&self, instruction: &Instruction) -> u32 {
        instruction
            .data
            .first()
            .filter(|_| instruction.program_id == self.ring.program_id())
            .and_then(|tag| InstructionTag::try_from(*tag).ok())
            .map_or(
                ComputeBudgetConfig::for_instruction_count(1).cu_limit,
                compute_unit_limit,
            )
    }
}

pub(crate) fn resolve(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() || path.starts_with("~") {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}
