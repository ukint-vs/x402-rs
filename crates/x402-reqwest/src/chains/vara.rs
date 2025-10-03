use async_trait::async_trait;
use gsdk::Keypair;
use rand::{Rng, rng};
use std::sync::Arc;
use x402_rs::network::NetworkFamily;
use x402_rs::timestamp::UnixTimestamp;
use x402_rs::types::{PaymentPayload, PaymentRequirements, VaraAddress, VaraNonce, VaraPaymentPayload, VaraSignature, ExactVaraPayload, ExactPaymentPayload, Scheme, X402Version};

use crate::X402PaymentsError;
use crate::chains::{IntoSenderWallet, SenderWallet};

#[derive(Clone)]
pub struct VaraSenderWallet {
    keypair: Arc<Keypair>,
}

impl VaraSenderWallet {
    pub fn new(keypair: Keypair) -> Self {
        Self {
            keypair: Arc::new(keypair),
        }
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

    async fn payment_payload(
        &self,
        selected: PaymentRequirements,
    ) -> Result<PaymentPayload, X402PaymentsError> {
        let contract_id = selected.asset.clone().try_into().map_err(|_| {
            X402PaymentsError::SigningError("Invalid asset address for Vara".to_string())
        })?;
        let from = VaraAddress::from_ss58(&self.keypair.public_key().to_ss58_address()).map_err(|e| {
            X402PaymentsError::SigningError(format!("Invalid signer address: {e}"))
        })?;
        let to = selected.pay_to.clone().try_into().map_err(|_| {
            X402PaymentsError::SigningError("Invalid pay_to address for Vara".to_string())
        })?;
        let amount = selected.max_amount_required;
        let now = UnixTimestamp::try_now().map_err(|e| X402PaymentsError::SigningError(format!("Clock error: {e:?}")))?;
        let valid_after = UnixTimestamp(now.seconds_since_epoch() - 10 * 60); // 10 mins before
        let valid_before = now + selected.max_timeout_seconds;
        let nonce_bytes: [u8; 32] = rng().random();
        let nonce = VaraNonce(nonce_bytes);

        let payload = VaraPaymentPayload {
            contract_id,
            from,
            to,
            amount,
            valid_after,
            valid_before,
            nonce,
            signature: VaraSignature(vec![]), // placeholder
        };

        // Serialize payload without signature for signing
        let payload_json = serde_json::to_string(&payload).map_err(|e| {
            X402PaymentsError::SigningError(format!("Serialization error: {e}"))
        })?;
        let message = payload_json.as_bytes();

        // Sign the message
        let signature = self.keypair.sign(message).map_err(|e| {
            X402PaymentsError::SigningError(format!("Signing error: {e}"))
        })?;
        let signature_bytes = signature.0;

        let signed_payload = VaraPaymentPayload {
            signature: VaraSignature(signature_bytes),
            ..payload
        };

        let payment_payload = PaymentPayload {
            x402_version: X402Version::V1,
            scheme: Scheme::Exact,
            network: selected.network,
            payload: ExactPaymentPayload::Vara(ExactVaraPayload {
                payload: signed_payload,
                metadata: None,
            }),
        };

        Ok(payment_payload)
    }
}
