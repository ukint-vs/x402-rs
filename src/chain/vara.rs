use std::str::FromStr;
use std::time::Duration;

use crate::chain::{FacilitatorLocalError, NetworkProviderOps};
use crate::facilitator::Facilitator;
use crate::network::Network;
use crate::types::{
    ExactPaymentPayload, MixedAddress, Scheme, SettleRequest, SettleResponse, SupportedPaymentKind,
    SupportedPaymentKindExtra, SupportedPaymentKindsResponse, TokenAmount, VaraAddress,
    VerifyRequest, VerifyResponse, X402Version,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sails_rs::calls::{Action, Call, Query};

use extended_vft_client::traits::Vft;
use gprimitives::{ActorId, MessageId};
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
    rpc_client: Api,
    signer: Signer,
    signer_address: ActorId,
}

impl VaraProvider {
    /// Create a new VaraProvider.
    pub async fn try_new(config: VaraConfig) -> Result<Self, FacilitatorLocalError> {
        let chain = VaraChain::new(config.network, config.rpc_url.clone());

        // let api = Api::new(config.rpc_url.clone()).await
        //     .map_err(|e| FacilitatorLocalError::InvalidSigner(format!("Failed to create API: {e}")))?;

        let (gear_api, signer) = if let Some(suri) = config.signer_suri {
            let gear_api = Api::new(config.rpc_url.as_str()).await.map_err(|e| {
                FacilitatorLocalError::InvalidSigner(format!("Failed to create API: {e}"))
            })?;

            let signer = Signer::new(gear_api.clone(), suri.as_str(), None).map_err(|e| {
                FacilitatorLocalError::InvalidSigner(format!("Failed to create Signer: {e}"))
            })?;
            (gear_api, signer)
        } else {
            return Err(FacilitatorLocalError::InvalidSigner(
                "signer_suri must be provided".to_string(),
            ));
        };

        Ok(Self {
            chain,
            rpc_client: gear_api,
            signer_address: ActorId::from_str(&signer.address()).expect("Valid address"),
            signer,
        })
    }

    async fn verify_transfer(
        &self,
        request: &VerifyRequest,
    ) -> Result<VerifyTransferResult, FacilitatorLocalError> {
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

        match (payment_payload.transaction.as_ref(), requirements.extra.as_ref()) {
            // Path B: wallet-signed raw extrinsic (payer provides signed tx)
            (Some(b64), maybe_extra) => {
                let bytes = BASE64
                    .decode(b64)
                    .map_err(|e| FacilitatorLocalError::DecodingError(format!("invalid base64 transaction: {e}")))?;
                // Require owner hint to define `payer`
                let owner_ss58 = maybe_extra
                    .and_then(|e| e.get("owner"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FacilitatorLocalError::DecodingError("missing `owner` in requirements.extra for signed transaction path".into()))?;
                let owner_id = parse_ss58(owner_ss58)?;
                let payer: VaraAddress = VaraAddress(owner_id);
                let auth_hash = sp_core::blake2_256(&bytes);
                Ok(VerifyTransferResult {
                    payer,
                    amount,
                    authorization_hash: auth_hash,
                })
            }
            // Path A: allowance + TransferFrom (relayer settles)
            (None, Some(extra)) => {
                let owner_ss58 = extra
                    .get("owner")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FacilitatorLocalError::DecodingError("missing `owner` in requirements.extra".into()))?;
                let _spender_ss58 = extra
                    .get("spender")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FacilitatorLocalError::DecodingError("missing `spender` in requirements.extra".into()))?;

                let owner_id = parse_ss58(owner_ss58)?;
                let payer: VaraAddress = VaraAddress(owner_id);

                // We don't fail on allowance/balance here yet; settlement will recheck and fail fast.
                let corr = sp_core::blake2_256(owner_ss58.as_bytes());
                Ok(VerifyTransferResult {
                    payer,
                    amount,
                    authorization_hash: corr,
                })
            }
            _ => Err(FacilitatorLocalError::InvalidSigner(
                "Provide either `payload.vara.transaction` (wallet-signed) or `requirements.extra.owner`+`spender` (allowance path)".to_string(),
            )),
        }
    }

    async fn read_allowance(
        &self,
        asset: ActorId,
        owner: ActorId,
        spender: ActorId,
    ) -> Result<U256, FacilitatorLocalError> {
        // Build a Sails remoting over the existing gsdk API client
        let remoting = GClientRemoting::new(self.rpc_client.clone().into());
        // Instantiate the generated VFT client bound to the target program (asset)
        let client = extended_vft_client::Vft::new(remoting);

        let recv_res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(
                // Call the query; the generated method name follows snake_case of the IDL "Allowance"
                client
                    .allowance(owner, spender)
                    .recv(asset)
            )
        });

        recv_res.map_err(|e| {
            FacilitatorLocalError::ContractCall(format!("VFT.TransferFrom failed: {e}"))
        })
    }

    async fn read_balance_of(
        &self,
        asset: ActorId,
        who: ActorId,
    ) -> Result<U256, FacilitatorLocalError> {
        use sails_rs::{futures::StreamExt, prelude::*};

        //  let remoting = sails_rs::client::GclientEnv::new(api.clone());
        let remoting = GClientRemoting::new(self.rpc_client.clone().into());

        let client = extended_vft_client::Vft::new(remoting);
            
        let recv_res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(
                // Call the query; the generated method name follows snake_case of the IDL "Allowance"
                client
                    .balance_of(who)
                    .recv(asset)
            )
        });

        recv_res.map_err(|e| {
            FacilitatorLocalError::ContractCall(format!("VFT.TransferFrom failed: {e}"))
        })
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

        // Optional safety check: ensure the declared spender equals our signer.
        if spender != self.signer_address {
            return Err(FacilitatorLocalError::InvalidSigner(format!(
                "spender {} does not match relayer {}",
                spender_ss58,
                self.signer.address()
            )));
        }

        // Fast-fail on insufficient allowance/balance.
        let allowance = self
            .read_allowance(program, owner, self.signer_address)
            .await?;
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
        let remoting = GClientRemoting::new(self.rpc_client.clone().into());
        let mut client = extended_vft_client::Vft::new(remoting);
        let send_res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(
                client
                    .transfer_from(owner, to, amount_u256)
                    .send(program),
            )
        });

        send_res.map_err(|e| {
            FacilitatorLocalError::ContractCall(format!("VFT.TransferFrom failed: {e}"))
        })?;

        // Build a correlation id (pre-settlement hash is still useful for the caller).
        // If you later expose the real extrinsic hash, replace this with it.
        let corr = sp_core::blake2_256(&(program, owner, to, amount_u256).encode());
        let payer: MixedAddress = verification.payer.clone().into();

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
        Ok(SupportedPaymentKindsResponse { kinds })
    }
}
