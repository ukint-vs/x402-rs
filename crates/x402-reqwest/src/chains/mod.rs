use std::sync::Arc;
use x402_rs::types::{PaymentPayload, PaymentRequirements};

use crate::X402PaymentsError;

pub mod evm;
pub mod solana;
pub mod vara;

#[async_trait::async_trait]
pub trait SenderWallet: Send + Sync {
    fn can_handle(&self, requirements: &PaymentRequirements) -> bool;
    async fn payment_payload(
        &self,
        selected: PaymentRequirements,
    ) -> Result<PaymentPayload, X402PaymentsError>;

    /// Approve allowance if needed (default no-op)
    async fn approve_if_needed(
        &self,
        _selected: &PaymentRequirements,
    ) -> Result<(), X402PaymentsError> {
        Ok(())
    }
}

pub trait IntoSenderWallet {
    fn into_sender_wallet(self) -> Arc<dyn SenderWallet>;
}
