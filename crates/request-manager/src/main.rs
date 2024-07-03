use axum::{extract::MatchedPath, http::Request, routing::post, Router};
use reqwest::Client;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing::{info, info_span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod handlers;
mod state;

use crate::{handlers::get_storage_value::get_storage_value, state::AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    setup_tracing();

    let app_state = AppState {
        client: Client::new(),
    };

    let app = create_router(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Listening on http://{}", listener.local_addr()?);

    axum::serve(listener, app).await?;

    Ok(())
}

fn setup_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            "request_manager=info,tower_http=debug,axum=info,tokio=info".into()
        }))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/get-storage", post(get_storage_value))
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
                let matched_path = request
                    .extensions()
                    .get::<MatchedPath>()
                    .map(MatchedPath::as_str);

                info_span!(
                    "http_request",
                    method = ?request.method(),
                    matched_path,
                    some_other_field = tracing::field::Empty,
                )
            }),
        )
        .with_state(app_state)
}
