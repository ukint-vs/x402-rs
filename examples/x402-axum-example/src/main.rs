use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use dotenvy::dotenv;
use opentelemetry::trace::Status;
use std::env;
use tower_http::trace::TraceLayer;
use tracing::instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use x402_axum::{IntoPriceTag, X402Middleware};
use x402_rs::network::{Network, USDCDeployment};
use x402_rs::telemetry::Telemetry;
use x402_rs::{address_evm, address_sol, address_vara};

#[tokio::main]
async fn main() {
    dotenv().ok();

    let _telemetry = Telemetry::new()
        .with_name(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .register();

    let facilitator_url = "http://localhost:8080".to_string();

    let x402 = X402Middleware::try_from(facilitator_url)
        .unwrap()
        .with_base_url(url::Url::parse("https://localhost:3000/").unwrap());
    let usdc_base_sepolia = USDCDeployment::by_network(Network::BaseSepolia)
        .pay_to(address_evm!("0xBAc675C310721717Cd4A37F6cbeA1F081b1C2a07"));
    let usdc_solana = USDCDeployment::by_network(Network::Solana)
        .pay_to(address_sol!("EGBQqKn968sVv5cQh5Cr72pSTHfxsuzq7o7asqYB5uEV"));
    let usdc_vara = USDCDeployment::by_network(Network::VaraTestnet).pay_to(address_vara!(
        "kGgadEFYMeg1gsYrbCyLdcSLa8HzR4x2RSj7Mep2RobUq8fao"
    ));

    let app = Router::new()
        .route(
            "/protected-route",
            get(my_handler).layer(
                x402.with_description("Premium API")
                    .with_mime_type("application/json")
                    .with_price_tag(usdc_vara.amount(0.0025).unwrap()),
            ),
        )
        .layer(
            // Usual HTTP tracing
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<_>| {
                    tracing::info_span!(
                        "http_request",
                        otel.kind = "server",
                        otel.name = %format!("{} {}", request.method(), request.uri()),
                        method = %request.method(),
                        uri = %request.uri(),
                        version = ?request.version(),
                    )
                })
                .on_response(
                    |response: &axum::http::Response<_>,
                     latency: std::time::Duration,
                     span: &tracing::Span| {
                        span.record("status", tracing::field::display(response.status()));
                        span.record("latency", tracing::field::display(latency.as_millis()));
                        span.record(
                            "http.status_code",
                            tracing::field::display(response.status().as_u16()),
                        );

                        // OpenTelemetry span status
                        if response.status().is_success()
                            || response.status() == StatusCode::PAYMENT_REQUIRED
                        {
                            span.set_status(Status::Ok);
                        } else {
                            span.set_status(Status::error(
                                response
                                    .status()
                                    .canonical_reason()
                                    .unwrap_or("unknown")
                                    .to_string(),
                            ));
                        }

                        tracing::info!(
                            "status={} elapsed={}ms",
                            response.status().as_u16(),
                            latency.as_millis()
                        );
                    },
                ),
        );

    tracing::info!("Using facilitator on {}", x402.facilitator_url());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Can not start server");
    tracing::info!("Listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[instrument(skip_all)]
async fn my_handler() -> impl IntoResponse {
    (StatusCode::OK, "This is a VIP content!")
}
