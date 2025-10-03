use std::str::FromStr;
use std::time::Duration;

use crate::chain::{FacilitatorLocalError, NetworkProviderOps};
use crate::facilitator::Facilitator;
use crate::network::Network;
use crate::timestamp::UnixTimestamp;
use crate::types::PaymentPayload;
use crate::types::TransactionHash;
use crate::types::VaraSignature;
use crate::types::{
    ExactPaymentPayload, FacilitatorErrorReason, MixedAddress, PaymentRequirements, Scheme,
    SettleRequest, SettleResponse, SupportedPaymentKind, SupportedPaymentKindExtra,
    SupportedPaymentKindsResponse, TokenAmount, VaraAddress, VerifyRequest, VerifyResponse,
    X402Version,
};
use extended_vft_client::vft::io::TransferFrom;
use gprimitives::{ActorId, MessageId, U256};
use gsdk::ext::sp_core::ByteArray;
use gsdk::ext::sp_runtime::AccountId32;
use gsdk::TxInBlock;
use gsdk::{Api, PairSigner, ext::sp_core::crypto::Ss58Codec, signer::Signer};
// use gclient::GearApi;

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
    pub signer_address: VaraAddress,
    pub signer_suri: Option<String>,
    pub gas_multiplier: f64,
    pub confirmation_timeout: Duration,
    pub max_gas_limit: u64,
}

impl VaraConfig {
    pub fn new(
        network: Network,
        rpc_url: impl Into<String>,
        signer_address: VaraAddress,
        signer_suri: Option<String>,
    ) -> Self {
        Self {
            network,
            rpc_url: rpc_url.into(),
            signer_address,
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

    fn stubbed_verify(&self, payer: MixedAddress) -> VerifyResponse {
        VerifyResponse::invalid(
            Some(payer),
            FacilitatorErrorReason::FreeForm("vara verification not implemented".to_string()),
        )
    }

    async fn verify_transfer(
        &self,
        request: &VerifyRequest,
    ) -> Result<VerifyTransferResult, FacilitatorLocalError> {
        let payload = &request.payment_payload;
        let requirements = &request.payment_requirements;

        // Assert valid payment START
        let payment_payload = match &payload.payload {
            ExactPaymentPayload::Evm(..) => {
                return Err(FacilitatorLocalError::UnsupportedNetwork(None));
            }
            ExactPaymentPayload::Solana(..) => {
                return Err(FacilitatorLocalError::UnsupportedNetwork(None));
            }
            ExactPaymentPayload::Vara(payload) => payload,
        };
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
        let transaction_b64_string = payment_payload.transaction.clone();
        // let bytes = Base64Bytes::from(transaction_b64_string.as_bytes())
        //     .decode()
        //     .map_err(|e| FacilitatorLocalError::DecodingError(format!("{e}")))?;
        // let transaction = bincode::deserialize::<VersionedTransaction>(bytes.as_slice())
        //     .map_err(|e| FacilitatorLocalError::DecodingError(format!("{e}")))?;

        // let payer: SolanaAddress = transfer_instruction.authority.into();
        // Ok(VerifyTransferResult { payer, transaction })
        todo!()
    }
}


pub struct VerifyTransferResult {
    pub payer: VaraAddress,
    pub transaction: TxInBlock,
}

impl NetworkProviderOps for VaraProvider {
    fn signer_address(&self) -> MixedAddress {
        self.signer_address.into()
    }

    fn network(&self) -> Network {
        self.chain.network
    }
}

impl Facilitator for VaraProvider {
    type Error = FacilitatorLocalError;

    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
        let verification = self.verify_transfer(request).await?;
        Ok(VerifyResponse::valid(verification.payer.into()))
    }

    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
        let verification = self.verify_transfer(request).await?;
        todo!()
        // Ok(SettleResponse {
        //     success: true,
        //     error_reason: None,
        //     payer,
        //     transaction: Some(TransactionHash::Vara(transaction_hash.into_bytes())),
        //     network: self.network(),
        // })
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
