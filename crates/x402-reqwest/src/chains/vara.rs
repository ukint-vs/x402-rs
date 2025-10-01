use async_trait::async_trait;
use std::sync::Arc;
use x402_rs::network::NetworkFamily;
use x402_rs::types::{PaymentPayload, PaymentRequirements, VaraAddress};

use crate::X402PaymentsError;
use crate::chains::{IntoSenderWallet, SenderWallet};

#[derive(Clone)]
pub struct VaraSenderWallet {
    _address: Arc<VaraAddress>,
}

impl VaraSenderWallet {
    pub fn new(address: VaraAddress) -> Self {
        Self {
            _address: Arc::new(address),
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
        _selected: PaymentRequirements,
    ) -> Result<PaymentPayload, X402PaymentsError> {
        Err(X402PaymentsError::SigningError(
            "Vara sender wallet not implemented".to_string(),
        ))
    }
}
