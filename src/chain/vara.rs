use std::time::Duration;

use crate::chain::{FacilitatorLocalError, NetworkProviderOps};
use crate::facilitator::Facilitator;
use crate::network::Network;
use crate::timestamp::UnixTimestamp;
use crate::types::{
    ExactPaymentPayload, FacilitatorErrorReason, MixedAddress, PaymentRequirements, Scheme,
    SettleRequest, SettleResponse, SupportedPaymentKind, SupportedPaymentKindExtra,
    SupportedPaymentKindsResponse, TokenAmount, VaraAddress, VaraPaymentPayload, VerifyRequest,
    VerifyResponse, X402Version,
};

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

/// Lightweight Vara Network provider stub.
#[derive(Clone, Debug)]
pub struct VaraProvider {
    chain: VaraChain,
    config: VaraConfig,
}

impl VaraProvider {
    pub async fn try_new(config: VaraConfig) -> Result<Self, FacilitatorLocalError> {
        let chain = VaraChain::new(config.network, config.rpc_url.clone());
        Ok(Self { chain, config })
    }

    fn ensure_scheme(&self, request: &VerifyRequest) -> Result<(), FacilitatorLocalError> {
        if request.payment_payload.scheme != Scheme::Exact
            || request.payment_requirements.scheme != Scheme::Exact
        {
            return Err(FacilitatorLocalError::SchemeMismatch(
                None,
                Scheme::Exact,
                request.payment_payload.scheme,
            ));
        }
        Ok(())
    }

    fn ensure_network(
        &self,
        request: &VerifyRequest,
        payer: Option<MixedAddress>,
    ) -> Result<(), FacilitatorLocalError> {
        if request.payment_payload.network != self.network() {
            return Err(FacilitatorLocalError::NetworkMismatch(
                payer.clone(),
                self.network(),
                request.payment_payload.network,
            ));
        }
        if request.payment_requirements.network != self.network() {
            return Err(FacilitatorLocalError::NetworkMismatch(
                payer,
                self.network(),
                request.payment_requirements.network,
            ));
        }
        Ok(())
    }

    fn ensure_receiver(
        &self,
        payload: &VaraPaymentPayload,
        requirements: &PaymentRequirements,
        payer: &MixedAddress,
    ) -> Result<(), FacilitatorLocalError> {
        let expected_receiver: VaraAddress =
            requirements.pay_to.clone().try_into().map_err(|_| {
                FacilitatorLocalError::InvalidAddress(
                    "expected Vara address for payment requirements".to_string(),
                )
            })?;
        if expected_receiver.to_ss58() != payload.to.to_ss58() {
            return Err(FacilitatorLocalError::ReceiverMismatch(
                payer.clone(),
                payload.to.to_ss58(),
                requirements.pay_to.to_string(),
            ));
        }
        Ok(())
    }

    fn ensure_amount(
        &self,
        payload: &VaraPaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<(), FacilitatorLocalError> {
        let expected: TokenAmount = requirements.max_amount_required;
        if payload.amount != expected {
            return Err(FacilitatorLocalError::InsufficientValue(
                payload.from.clone().into(),
            ));
        }
        Ok(())
    }

    fn ensure_time_window(
        &self,
        payload: &VaraPaymentPayload,
        payer: &MixedAddress,
    ) -> Result<(), FacilitatorLocalError> {
        let now = UnixTimestamp::try_now().map_err(FacilitatorLocalError::ClockError)?;
        if payload.valid_after > now {
            return Err(FacilitatorLocalError::InvalidTiming(
                payer.clone(),
                "payment not yet valid".to_string(),
            ));
        }
        if payload.valid_before <= now {
            return Err(FacilitatorLocalError::InvalidTiming(
                payer.clone(),
                "payment authorization expired".to_string(),
            ));
        }
        Ok(())
    }

    fn extract_payload<'a>(
        &'a self,
        request: &'a VerifyRequest,
    ) -> Result<&'a VaraPaymentPayload, FacilitatorLocalError> {
        match &request.payment_payload.payload {
            ExactPaymentPayload::Vara(payload) => Ok(&payload.payload),
            _ => Err(FacilitatorLocalError::UnsupportedNetwork(None)),
        }
    }

    fn stubbed_verify(&self, payer: MixedAddress) -> VerifyResponse {
        VerifyResponse::invalid(
            Some(payer),
            FacilitatorErrorReason::FreeForm("vara verification not implemented".to_string()),
        )
    }

    fn stubbed_settle_response(&self, payer: MixedAddress) -> SettleResponse {
        SettleResponse {
            success: false,
            error_reason: Some(FacilitatorErrorReason::FreeForm(
                "vara settlement not implemented".to_string(),
            )),
            payer,
            transaction: None,
            network: self.network(),
        }
    }
}

impl NetworkProviderOps for VaraProvider {
    fn signer_address(&self) -> MixedAddress {
        self.config.signer_address.clone().into()
    }

    fn network(&self) -> Network {
        self.chain.network
    }
}

impl Facilitator for VaraProvider {
    type Error = FacilitatorLocalError;

    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
        self.ensure_scheme(request)?;
        let payload = self.extract_payload(request)?;
        let payer: MixedAddress = payload.from.clone().into();
        self.ensure_network(request, Some(payer.clone()))?;
        self.ensure_receiver(payload, &request.payment_requirements, &payer)?;
        self.ensure_amount(payload, &request.payment_requirements)?;
        self.ensure_time_window(payload, &payer)?;
        Ok(self.stubbed_verify(payer))
    }

    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
        self.ensure_scheme(request)?;
        let payload = self.extract_payload(request)?;
        let payer: MixedAddress = payload.from.clone().into();
        self.ensure_network(request, Some(payer.clone()))?;
        self.ensure_receiver(payload, &request.payment_requirements, &payer)?;
        self.ensure_amount(payload, &request.payment_requirements)?;
        self.ensure_time_window(payload, &payer)?;
        Ok(self.stubbed_settle_response(payer))
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
