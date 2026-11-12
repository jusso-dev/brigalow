//! Offline operator command. No HTTP endpoint, HSM access or automatic migration.
use brigalow_server::config::Config;
use brigalow_store::admin::Admin;
use clap::{Parser, Subcommand};
use uuid::Uuid;
#[derive(Parser)]
#[command(about = "Operator-only database migration and tenant bootstrap")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Migrate,
    OrgCreate {
        #[arg(long)]
        org: Uuid,
        #[arg(long)]
        name: String,
    },
}
async fn run(args: Args) -> Result<(), ()> {
    let config = Config::load().map_err(|_| ())?;
    let admin = Admin::connect(config.database_options())
        .await
        .map_err(|_| ())?;
    let result = match args.command {
        Command::Migrate => admin.migrate().await,
        Command::OrgCreate { org, name } => admin.create_org(org, &name).await.map(|_| ()),
    };
    admin.close().await;
    result.map_err(|_| ())
}
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run(Args::parse()).await {
        Ok(()) => {
            println!("Operator operation completed");
            std::process::ExitCode::SUCCESS
        }
        Err(()) => {
            eprintln!(
                "Operator operation failed; check owner credentials, TLS, schema and arguments"
            );
            std::process::ExitCode::FAILURE
        }
    }
}
