use async_trait::async_trait;
use extended_vft_client::traits::Vft;
use gclient::GearApi;
use gsdk::PairSigner;
use gsdk::metadata::runtime_types::gprimitives;
use sails_rs::calls::Call;
use sails_rs::calls::Remoting;
use sails_rs::gclient::calls::GClientRemoting;
use std::str::FromStr;
// use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
use x402_rs::network::NetworkFamily;
use x402_rs::types::{
    ExactPaymentPayload, ExactVaraPayload, PaymentPayload, PaymentRequirements, Scheme,
    TokenAmount, VaraPayloadMetadata, X402Version,
};

use crate::X402PaymentsError;
use crate::chains::{IntoSenderWallet, SenderWallet};

/// Vara provider for contract interactions using sails-rs
#[derive(Clone)]
pub struct VaraProvider {
    remoting: GClientRemoting,
}

impl VaraProvider {
    /// Create a new VaraProvider with a GearApi connection
    pub fn new(api: GearApi) -> Self {
        Self {
            remoting: GClientRemoting::new(api),
        }
    }

    /// Get the underlying remoting instance for contract calls
    pub fn remoting(&self) -> &GClientRemoting {
        &self.remoting
    }

    /// Approve allowance for a spender
    pub async fn approve(
        &self,
        asset: sails_rs::ActorId,
        spender: sails_rs::ActorId,
        amount: sails_rs::U256,
    ) -> Result<(), X402PaymentsError> {
        use extended_vft_client::Vft;

        let mut client = Vft::new(self.remoting.clone());
        // Check allowance first (optional but nice)
        // let current = client
        //     .allowance(owner_signer.address(), spender)
        //     .call()
        //     .await?;
        // if current < amount_u256 {
        //     // Approve from the OWNER (payer pays this one-time gas)
        //     vft.at(asset)
        //         .approve(spender, amount_u256.clone())
        //         .send(&owner_signer)
        //         .await?;
        // }

        print!(
            "Approving allowance of {} for spender {} on asset {}",
            amount, spender, asset
        );

        let send_res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.approve(spender, amount * 2).send(asset))
        });

        send_res
            .map_err(|e| X402PaymentsError::SigningError(format!("VFT.Approve failed: {e}")))?;

        Ok(())
    }

    /// Estimate gas for a contract call
    pub async fn estimate_gas(
        &self,
        target: sails_rs::ActorId,
        payload: impl AsRef<[u8]> + Send + Sync,
        value: u128,
    ) -> Result<u64, X402PaymentsError> {
        // Use calculate_handle_gas for estimation through remoting
        // let gas_limit = self
        //     .remoting.clone()
        //     .query(target, payload, Some(0), value, Default::default())
        //     .await
        //     .map_err(|e| X402PaymentsError::SigningError(format!("Gas estimation failed: {e}")))?;

        // For now, return a default gas limit since sails-rs handles this internally
        // In practice, this would be extracted from the simulation
        Ok(1_000_000_000_000) // Default gas limit
    }
}

#[derive(Clone)]
pub struct VaraSenderWallet {
    gear_api: Arc<GearApi>,
    provider: Option<Arc<VaraProvider>>,
}

impl VaraSenderWallet {
    pub fn new(api: GearApi) -> Self {
        Self {
            gear_api: Arc::new(api),
            provider: None,
        }
    }

    pub fn with_provider(api: GearApi, provider: VaraProvider) -> Self {
        Self {
            gear_api: Arc::new(api),
            provider: Some(Arc::new(provider)),
        }
    }

    /// Get the provider if available
    pub fn provider(&self) -> Option<&Arc<VaraProvider>> {
        self.provider.as_ref()
    }
}

impl IntoSenderWallet for VaraSenderWallet {
    fn into_sender_wallet(self) -> Arc<dyn SenderWallet> {
        Arc::new(self)
    }
}

#[async_trait]
impl SenderWallet for VaraSenderWallet {
    fn can_handle(&self, requirements: &PaymentRequirements) -> bool {
        let network_family: NetworkFamily = requirements.network.into();
        matches!(network_family, NetworkFamily::Vara)
    }

    async fn approve_if_needed(
        &self,
        selected: &PaymentRequirements,
    ) -> Result<(), X402PaymentsError> {
        // For Vara, we need to approve the facilitator (spender) to spend the amount
        let extra = selected.extra.as_ref().ok_or_else(|| {
            X402PaymentsError::SigningError("missing extra for Vara approval".to_string())
        })?;
        let spender_ss58 = extra
            .get("spender")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                X402PaymentsError::SigningError("missing spender in extra".to_string())
            })?;
        let spender = sails_rs::ActorId::from_str(spender_ss58)
            .map_err(|e| X402PaymentsError::SigningError(format!("Invalid spender SS58: {e}")))?;
        let asset = sails_rs::ActorId::from_str(&selected.asset.to_string())
            .map_err(|e| X402PaymentsError::SigningError(format!("Invalid asset SS58: {e}")))?;
        let amount = selected.max_amount_required;
        let amount_u256: sails_rs::U256 = sails_rs::U256(*amount.0.as_limbs());

        // Create provider if not present
        let provider = self.provider.clone().unwrap_or_else(|| {
            let remoting = GClientRemoting::new((*self.gear_api).clone().into());
            Arc::new(VaraProvider { remoting })
        });

        provider.approve(asset, spender, amount_u256).await
    }

    async fn payment_payload(
        &self,
        selected: PaymentRequirements,
    ) -> Result<PaymentPayload, X402PaymentsError> {
        info!(
            "Creating Vara payment payload for amount {}",
            selected.max_amount_required
        );

        // Vara / VFT path for x402 in reqwest: we emit a payload for the **relayer** flow.
        // No authorization objects, no signed transaction blob — the facilitator will
        // perform Allowance+TransferFrom on-chain.

        // Exact amount to be paid (base units) comes straight from requirements.
        let amount: TokenAmount = selected.max_amount_required;

        // Provide a conservative gas hint; a provider-based estimator can overwrite this later.
        let gas_limit: u64 = 1_000_000_000_000;

        let payload = PaymentPayload {
            x402_version: X402Version::V1,
            scheme: Scheme::Exact,
            network: selected.network,
            payload: ExactPaymentPayload::Vara(ExactVaraPayload {
                // Non-binding execution hints for the facilitator.
                metadata: VaraPayloadMetadata {
                    gas_limit,
                    value: amount,
                },
            }),
        };

        info!("Vara payment payload created successfully");
        Ok(payload)
    }
}
