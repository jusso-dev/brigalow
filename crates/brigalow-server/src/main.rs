use brigalow_server::{
    application,
    auth::{Identity, IdentityConfig},
    config::{Config, Mode},
    AppState,
};
use brigalow_store::Store;
use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt};

async fn run() -> Result<(), &'static str> {
    let config = Config::load().map_err(|error| {
        tracing::error!(%error, "configuration rejected");
        "invalid configuration"
    })?;
    let keys = config
        .key_backend()
        .map_err(|e| {
            tracing::error!(error=%e,"key backend startup rejected");
            "key backend startup failed"
        })?
        .map(|backend| -> Result<_, &'static str> {
            let anchors = config
                .trust_anchors
                .iter()
                .map(|path| {
                    if path.name.is_empty()
                        || path.name.len() > 200
                        || !matches!(
                            path.tier,
                            brigalow_core::TrustTier::Private
                                | brigalow_core::TrustTier::ExternalCa
                        )
                    {
                        return Err("invalid trust anchor configuration");
                    }
                    let der = std::fs::read(&path.file).map_err(|_| "cannot read trust anchor")?;
                    if der.len() > 65536 {
                        return Err("trust anchor too large");
                    }
                    Ok(brigalow_server::keys::Anchor {
                        name: path.name.clone(),
                        tier: path.tier,
                        der,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(brigalow_server::keys::KeyService {
                backend,
                id: config.backend_id.clone(),
                anchors,
            })
        })
        .transpose()?;
    let tsa = config
        .tsa
        .as_ref()
        .map(|t| t.client())
        .transpose()
        .map_err(|_| "invalid TSA configuration")?;
    let gates = brigalow_server::gates::Gates::new(&config.gates)?;
    let notifications = brigalow_server::notifications::Notifications::new(&config.notifications)?;
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
    tracing::info!(address = %listener.local_addr().map_err(|_| "cannot inspect listener")?, mode = ?config.mode, "server listening");
    let identity = match std::env::var("BRIGALOW_IDENTITY_FILE") {
        Ok(path) => {
            let bytes = std::fs::read(path).map_err(|_| "cannot read identity configuration")?;
            let settings: IdentityConfig =
                serde_json::from_slice(&bytes).map_err(|_| "invalid identity configuration")?;
            Some(
                Identity::new(settings, config.mode)
                    .map_err(|_| "invalid identity configuration")?,
            )
        }
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => return Err("invalid identity configuration path"),
    };
    let expiry_task = identity.as_ref().map(|identity| {
        let orgs = identity
            .config
            .authorities
            .iter()
            .map(|a| a.org_id)
            .collect::<std::collections::BTreeSet<_>>();
        let store = store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                for org in &orgs {
                    if store.tenant(*org).expire_requests().await.is_err() {
                        tracing::warn!("approval expiry maintenance failed");
                    }
                }
            }
        })
    });
    let result = axum::serve(
        listener,
        application(AppState {
            rate_limit: config.rate_limit,
            store: store.clone(),
            mode: config.mode,
            identity,
            keys,
            tsa,
            notifications,
            gates,
        }),
    )
    .with_graceful_shutdown(shutdown())
    .await;
    if let Some(task) = expiry_task {
        task.abort();
    }
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
