use brigalow_server::{
    config::{Config, Mode},
    router,
};
use brigalow_store::Store;
use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt};

async fn run() -> Result<(), &'static str> {
    let config = Config::load().map_err(|error| {
        tracing::error!(%error, "configuration rejected");
        "invalid configuration"
    })?;
    let store = Store::connect(config.database_options()).await.map_err(|_| {
        tracing::error!(?config, "database startup failed; check availability, TLS, migrations and restricted runtime role");
        "database startup failed"
    })?;
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|_| {
            tracing::error!(?config, "listener startup failed");
            "listener startup failed"
        })?;
    if config.mode == Mode::Lab {
        tracing::warn!("LAB MODE: test use only; release signing unavailable");
    }
    tracing::info!(address = %listener.local_addr().map_err(|_| "cannot inspect listener")?, mode = ?config.mode, "server listening; signing unavailable in Phase 0");
    let result = axum::serve(listener, router(store.clone(), config.mode))
        .with_graceful_shutdown(shutdown())
        .await;
    store.close().await;
    result.map_err(|_| "HTTP server stopped unexpectedly")
}
async fn shutdown() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Fixed application-only log targets: RUST_LOG cannot enable credential-bearing dependency logs.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(std::io::stderr),
        )
        .with(Targets::new().with_target("brigalow_server", tracing::Level::INFO))
        .init();
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error, "server stopped");
            std::process::ExitCode::FAILURE
        }
    }
}
