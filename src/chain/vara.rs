use std::str::FromStr;
use std::time::Duration;
use gclient::GearApi;
use tracing::{debug, info, warn};

use crate::chain::{FacilitatorLocalError, NetworkProviderOps};
use crate::facilitator::Facilitator;
use crate::network::Network;
use crate::types::{
    ExactPaymentPayload, MixedAddress, Scheme, SettleRequest, SettleResponse, SupportedPaymentKind,
    SupportedPaymentKindExtra, SupportedPaymentKindsResponse, TokenAmount, VaraAddress,
    VerifyRequest, VerifyResponse, X402Version,
};
use sails_rs::calls::{Action, Call, Query};

use extended_vft_client::traits::Vft;
use gprimitives::ActorId;
use gsdk::ext::sp_core;
use gsdk::{Api, signer::Signer};
use parity_scale_codec::Encode;
use sails_rs::U256;
use sails_rs::gclient::calls::GClientRemoting;

/// Vara network metadata describing RPC and timing parameters.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct VaraChain {
    pub network: Network,
    pub rpc_url: String,
    pub block_time: Duration,
    pub ss58_prefix: u16,
}

impl VaraChain {
    pub fn new(network: Network, rpc_url: impl Into<String>) -> Self {
        let block_time = Duration::from_secs(3);
        let ss58_prefix = network.vara_ss58_prefix();
        Self {
            network,
            rpc_url: rpc_url.into(),
            block_time,
            ss58_prefix,
        }
    }
}

/// Configuration required to instantiate a [`VaraProvider`].
#[derive(Clone, Debug)]
pub struct VaraConfig {
    pub network: Network,
    pub rpc_url: String,
    // pub signer_address: VaraAddress,
    pub signer_suri: Option<String>,
    pub gas_multiplier: f64,
    pub confirmation_timeout: Duration,
    pub max_gas_limit: u64,
}

impl VaraConfig {
    pub fn new(network: Network, rpc_url: impl Into<String>, signer_suri: Option<String>) -> Self {
        Self {
            network,
            rpc_url: rpc_url.into(),
            // signer_address,
            signer_suri,
            gas_multiplier: 1.1,
            confirmation_timeout: Duration::from_secs(30),
            max_gas_limit: 100_000_000,
        }
    }
}

#[derive(Clone)]
pub struct VaraProvider {
    chain: VaraChain,
    rpc_client: GearApi,
    signer_address: ActorId,
}

impl VaraProvider {
    /// Create a new VaraProvider.
    pub async fn try_new(config: VaraConfig) -> Result<Self, FacilitatorLocalError> {
        let chain = VaraChain::new(config.network, config.rpc_url.clone());

        // let api = Api::new(config.rpc_url.clone()).await
        //     .map_err(|e| FacilitatorLocalError::InvalidSigner(format!("Failed to create API: {e}")))?;

        let gear_api = if let Some(suri) = config.signer_suri {
            let gear_api = GearApi::builder()
                .suri(&suri)
                .build(gclient::WSAddress::vara_testnet())
                .await
                .map_err(|e| {
                    FacilitatorLocalError::InvalidSigner(format!("Failed to create GearApi: {e}"))
                })?;
            gear_api
        } else {
            return Err(FacilitatorLocalError::InvalidSigner(
                "signer_suri must be provided".to_string(),
            ));
        };

        Ok(Self {
            chain,
            signer_address: ActorId::from_str(&gear_api.account_id().to_string()).expect("Valid address"),
            rpc_client: gear_api,
        })
    }

    async fn verify_transfer(
        &self,
        request: &VerifyRequest,
    ) -> Result<VerifyTransferResult, FacilitatorLocalError> {
        info!("Starting Vara payment verification");

        let payload = &request.payment_payload;
        let requirements = &request.payment_requirements;

        // Only Vara + Exact scheme supported here
        let payment_payload = match &payload.payload {
            ExactPaymentPayload::Evm(..) => {
                return Err(FacilitatorLocalError::UnsupportedNetwork(None));
            }
            ExactPaymentPayload::Solana(..) => {
                return Err(FacilitatorLocalError::UnsupportedNetwork(None));
            }
            ExactPaymentPayload::Vara(p) => p,
        };

        // Network & scheme checks
        if payload.network != self.network() {
            return Err(FacilitatorLocalError::NetworkMismatch(
                None,
                self.network(),
                payload.network,
            ));
        }
        if requirements.network != self.network() {
            return Err(FacilitatorLocalError::NetworkMismatch(
                None,
                self.network(),
                requirements.network,
            ));
        }
        if payload.scheme != requirements.scheme {
            return Err(FacilitatorLocalError::SchemeMismatch(
                None,
                requirements.scheme,
                payload.scheme,
            ));
        }

        let amount: TokenAmount = requirements.max_amount_required;

        let extra = requirements.extra.as_ref().ok_or_else(|| {
            FacilitatorLocalError::DecodingError(
                "missing `requirements.extra` for relayed Vara payments".into(),
            )
        })?;
        // debug!("requirements.extra keys: {:?}", extra.keys().collect::<Vec<_>>());

        debug!("requirements.extra: {:?}", extra);
        let owner_ss58 = extra.get("owner").and_then(|v| v.as_str()).ok_or_else(|| {
            FacilitatorLocalError::DecodingError(
                "missing `owner` in requirements.extra (payer SS58)".into(),
            )
        })?;

        // Ensure spender is present too (we don't compare here; settle() enforces spender==relayer)
        let _spender_ss58 = extra
            .get("spender")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                FacilitatorLocalError::DecodingError(
                    "missing `spender` in requirements.extra (relayer SS58)".into(),
                )
            })?;

        let owner_id = parse_ss58(owner_ss58)?;
        let payer: VaraAddress = VaraAddress(owner_id);

        // Correlation id for verify→settle; not an on-chain extrinsic hash.
        let corr = sp_core::blake2_256(owner_ss58.as_bytes());
        info!(
            "Vara verify: owner {}, amount {}, corr {:x?}",
            owner_ss58, amount, corr
        );
        info!("Vara payment verification completed successfully");
        Ok(VerifyTransferResult {
            payer,
            amount,
            authorization_hash: corr,
        })
    }

    async fn read_allowance(
        &self,
        asset: ActorId,
        owner: ActorId,
        spender: ActorId,
    ) -> Result<U256, FacilitatorLocalError> {
        info!("Reading allowance for asset {}, owner {}, spender {}", asset, owner, spender);
        // Build a Sails remoting over the existing gsdk API client
        let remoting = GClientRemoting::new(self.rpc_client.clone().into());
        // Instantiate the generated VFT client bound to the target program (asset)
        let client = extended_vft_client::Vft::new(remoting);

        let recv_res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(
                // Call the query; the generated method name follows snake_case of the IDL "Allowance"
                client.allowance(owner, spender).recv(asset),
            )
        });

        let allowance = recv_res.map_err(|e| {
            FacilitatorLocalError::ContractCall(format!("VFT.ReadAllowance failed: {e}"))
        })?;
        info!("Allowance read successfully: {}", allowance);
        Ok(allowance)
    }

    async fn read_balance_of(
        &self,
        asset: ActorId,
        who: ActorId,
    ) -> Result<U256, FacilitatorLocalError> {
        info!("Reading balance for asset {}, who {}", asset, who);
        use sails_rs::{futures::StreamExt, prelude::*};

        //  let remoting = sails_rs::client::GclientEnv::new(api.clone());
        let remoting = GClientRemoting::new(self.rpc_client.clone().into());

        let client = extended_vft_client::Vft::new(remoting);

        let recv_res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(
                // Call the query; the generated method name follows snake_case of the IDL "Allowance"
                client.balance_of(who).recv(asset),
            )
        });

        let balance = recv_res.map_err(|e| {
            FacilitatorLocalError::ContractCall(format!("VFT.ReadBalance failed: {e}"))
        })?;
        info!("Balance read successfully: {}", balance);
        Ok(balance)
    }

    // Back-compat with earlier call sites in this module
    async fn read_balance(
        &self,
        asset: ActorId,
        who: ActorId,
    ) -> Result<U256, FacilitatorLocalError> {
        self.read_balance_of(asset, who).await
    }
}

pub struct VerifyTransferResult {
    /// Payer (owner) inferred from requirements.extra or decoded signer
    pub payer: VaraAddress,
    /// Exact token amount (base units)
    pub amount: TokenAmount,
    /// Stable correlation id (not an on-chain extrinsic hash)
    pub authorization_hash: [u8; 32],
}

impl NetworkProviderOps for VaraProvider {
    fn signer_address(&self) -> MixedAddress {
        self.signer_address.into()
    }

    fn network(&self) -> Network {
        self.chain.network
    }
}

/// Parse an SS58 address into an `ActorId`.
/// Accepts any SS58 string understood by `ActorId::from_str`.
/// Returns a `FacilitatorLocalError::DecodingError` on failure.
fn parse_ss58<S: AsRef<str>>(addr: S) -> Result<ActorId, FacilitatorLocalError> {
    let s = addr.as_ref().trim();
    ActorId::from_str(s).map_err(|e| {
        FacilitatorLocalError::DecodingError(format!("Invalid SS58 address `{}`: {e}", s))
    })
}

/// Convert TokenAmount into sails_rs::U256 via string representation.
/// Assumes TokenAmount implements Display (serde/json fallback could be used otherwise).
fn token_to_u256(amount: &TokenAmount) -> U256 {
    U256(*amount.0.as_limbs())
}

impl Facilitator for VaraProvider {
    type Error = FacilitatorLocalError;

    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
        let verification = self.verify_transfer(request).await?;
        Ok(VerifyResponse::valid(verification.payer.into()))
    }

    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
        info!("Starting Vara payment settlement");

        // Prefer the relayer (TransferFrom) path when `transaction` is not provided.
        // We still reuse verification to validate network/scheme and compute payer.
        let verify_request = VerifyRequest {
            x402_version: request.x402_version,
            payment_payload: request.payment_payload.clone(),
            payment_requirements: request.payment_requirements.clone(),
        };
        let verification = self.verify_transfer(&verify_request).await?;

        // Extract commonly used fields
        let requirements = &request.payment_requirements;
        let amount_u256: U256 = token_to_u256(&requirements.max_amount_required);

        // Resolve program (asset) and recipient (pay_to) from MixedAddress via SS58 round-trip.
        let program: ActorId = parse_ss58(requirements.asset.to_string())?;
        let to: ActorId = parse_ss58(requirements.pay_to.to_string())?;

        // Parse `owner` and `spender` (relayer) from `extra`.
        let extra = requirements.extra.as_ref().ok_or_else(|| {
            FacilitatorLocalError::DecodingError(
                "missing `requirements.extra` for relayer path".into(),
            )
        })?;
        let owner_ss58 = extra.get("owner").and_then(|v| v.as_str()).ok_or_else(|| {
            FacilitatorLocalError::DecodingError("missing `owner` in requirements.extra".into())
        })?;
        let spender_ss58 = extra
            .get("spender")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                FacilitatorLocalError::DecodingError(
                    "missing `spender` in requirements.extra".into(),
                )
            })?;

        let owner: ActorId = parse_ss58(owner_ss58)?;
        let spender: ActorId = parse_ss58(spender_ss58)?;

        debug!(
            owner = %owner_ss58,
            spender = %spender_ss58,
            signer = %self.signer_address,
            "Parsed Vara extra fields"
        );

        // Optional safety check: ensure the declared spender equals our signer.
        if spender != self.signer_address {
            warn!(
                expected = %self.signer_address,
                got = %spender_ss58,
                "Relayer mismatch detected during Vara settlement"
            );
            return Err(FacilitatorLocalError::InvalidSigner(format!(
                "spender {} does not match relayer {}",
                spender_ss58,
                self.signer_address
            )));
        }

        // Fast-fail on insufficient allowance/balance.
        debug!("Checking allowance and balance for Vara payment");
        let allowance = self
            .read_allowance(program, owner, self.signer_address)
            .await?;
        tracing::debug!(%allowance, "Read allowance");
        if allowance < amount_u256 {
            return Err(FacilitatorLocalError::ContractCall(
                "insufficient allowance".to_string(),
            ));
        }
        let balance = self.read_balance(program, owner).await?;
        if balance < amount_u256 {
            return Err(FacilitatorLocalError::ContractCall(
                "insufficient balance".to_string(),
            ));
        }

        // Send TransferFrom(owner -> to, amount) as the RELAYER (our signer).
        // Run non-Send Sails `.send(...)` inside a blocking section bound to the current runtime.
        info!(
            "Executing Vara transfer: from {} to {} amount {}",
            owner_ss58, requirements.pay_to, amount_u256
        );
        let remoting = GClientRemoting::new(self.rpc_client.clone().into());
        let mut client = extended_vft_client::Vft::new(remoting);
        let send_res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(client.transfer_from(owner, to, amount_u256).send(program))
        });

        send_res.map_err(|e| {
            FacilitatorLocalError::ContractCall(format!("VFT.TransferFrom failed: {e}"))
        })?;

        info!("Vara transfer completed successfully");

        // Build a correlation id (pre-settlement hash is still useful for the caller).
        // If you later expose the real extrinsic hash, replace this with it.
        let corr = sp_core::blake2_256(&(program, owner, to, amount_u256).encode());
        let payer: MixedAddress = verification.payer.clone().into();

        info!("Vara payment settlement completed successfully");
        Ok(SettleResponse {
            success: true,
            error_reason: None,
            payer,
            transaction: Some(crate::types::TransactionHash::Vara(corr)),
            network: self.network(),
        })
    }

    async fn supported(&self) -> Result<SupportedPaymentKindsResponse, Self::Error> {
        let kinds = vec![SupportedPaymentKind {
            x402_version: X402Version::V1,
            scheme: Scheme::Exact,
            network: self.network(),
            extra: Some(SupportedPaymentKindExtra {
                fee_payer: self.signer_address(),
            }),
        }];
        tracing::debug!(?kinds, "Vara supported kinds");
        Ok(SupportedPaymentKindsResponse { kinds })
    }
}
