//! Extension traits and builders for ergonomic integration of [`X402Payments`] middleware
//! into [`reqwest::Client`] or [`reqwest::ClientBuilder`] instances.
//!
//! This allows code like:
//!
//! ```rust,no_run
//! use reqwest::Client;
//! use x402_reqwest::{ReqwestWithPayments, ReqwestWithPaymentsBuild};
//! use alloy::signers::local::PrivateKeySigner;
//!
//! let signer: PrivateKeySigner = "...".parse().unwrap();
//!
//! let client: reqwest_middleware::ClientWithMiddleware = Client::new()
//!     .with_payments(signer)
//!     .prefer(...)
//!     .max(...)
//!     .build();
//! ```

use reqwest::{Client, ClientBuilder};
use reqwest_middleware as rqm;
use reqwest_middleware::ClientWithMiddleware;
use x402_rs::types::TokenAsset;

use crate::chains::IntoSenderWallet;
use crate::{MaxTokenAmount, X402Payments};

/// Builder for attaching `X402Payments` middleware to a `reqwest` client or builder.
///
/// This allows configuration of payment-related settings (like preferred tokens or max token amounts)
/// before finalizing into a `ClientWithMiddleware`.
pub struct ReqwestWithPaymentsBuilder<A> {
    inner: A,
    x402: X402Payments,
}

impl<A> ReqwestWithPaymentsBuilder<A> {
    pub fn and_with_wallet<S: IntoSenderWallet>(self, wallet: S) -> Self {
        Self {
            inner: self.inner,
            x402: self.x402.and_with_wallet(wallet),
        }
    }

    /// Set the maximum amount allowed to be paid for a given token.
    /// This is enforced before any request is retried with a payment header.
    /// Mimics [`X402Payments::max`].
    pub fn max(self, max: MaxTokenAmount) -> Self {
        Self {
            inner: self.inner,
            x402: self.x402.max(max),
        }
    }

    /// Extend the list of preferred tokens to use for payment,
    /// prioritized during requirement selection.
    /// Mimics [`X402Payments::prefer`].
    pub fn prefer<T: Into<Vec<TokenAsset>>>(self, prefer: T) -> Self {
        Self {
            inner: self.inner,
            x402: self.x402.prefer(prefer),
        }
    }

    /// Attach the Vara payer address so the middleware can populate the required header automatically.
    pub fn vara_owner<S: Into<String>>(self, owner_ss58: S) -> Self {
        Self {
            inner: self.inner,
            x402: self.x402.vara_owner(owner_ss58),
        }
    }
}

/// A trait implemented for both builder variants to finalize the HTTP client.
pub trait ReqwestWithPaymentsBuild {
    type BuildResult;
    type BuilderResult;

    /// Finalize the middleware-enhanced client, producing a [`ClientWithMiddleware`].
    fn build(self) -> Self::BuildResult;

    /// Produce a [`Self::BuildResult`] to further customize the reqwest http client.
    fn builder(self) -> Self::BuilderResult;
}

impl ReqwestWithPaymentsBuild for ReqwestWithPaymentsBuilder<Client> {
    type BuildResult = ClientWithMiddleware;
    type BuilderResult = rqm::ClientBuilder;

    fn build(self) -> Self::BuildResult {
        self.builder().build()
    }

    fn builder(self) -> Self::BuilderResult {
        rqm::ClientBuilder::new(self.inner).with(self.x402)
    }
}

impl ReqwestWithPaymentsBuild for ReqwestWithPaymentsBuilder<ClientBuilder> {
    type BuildResult = Result<ClientWithMiddleware, reqwest::Error>;
    type BuilderResult = Result<rqm::ClientBuilder, reqwest::Error>;

    fn build(self) -> Self::BuildResult {
        let builder = self.builder()?;
        Ok(builder.build())
    }

    fn builder(self) -> Self::BuilderResult {
        let client = self.inner.build()?;
        Ok(rqm::ClientBuilder::new(client).with(self.x402))
    }
}

/// Extension trait that adds `.with_payments(...)` to [`reqwest::Client`] and [`reqwest::ClientBuilder`],
/// returning a [`ReqwestWithPaymentsBuilder`] that can be further customized.
pub trait ReqwestWithPayments {
    type Inner;

    /// Wraps the base client with an [`X402Payments`] middleware using the given signer.
    fn with_payments<S: IntoSenderWallet>(
        self,
        wallet: S,
    ) -> ReqwestWithPaymentsBuilder<Self::Inner>;
}

impl ReqwestWithPayments for Client {
    type Inner = Client;

    fn with_payments<S: IntoSenderWallet>(
        self,
        wallet: S,
    ) -> ReqwestWithPaymentsBuilder<Self::Inner> {
        ReqwestWithPaymentsBuilder {
            inner: self,
            x402: X402Payments::with_wallet(wallet),
        }
    }
}

impl ReqwestWithPayments for ClientBuilder {
    type Inner = ClientBuilder;

    fn with_payments<S: IntoSenderWallet>(
        self,
        wallet: S,
    ) -> ReqwestWithPaymentsBuilder<Self::Inner> {
        ReqwestWithPaymentsBuilder {
            inner: self,
            x402: X402Payments::with_wallet(wallet),
        }
    }
}
