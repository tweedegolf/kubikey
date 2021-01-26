use time::Format;
use clap::Clap;

use token::{get_id_token, get_access_token};

mod token;
mod yubikey;
mod config;

/// Kubikey is a tool for using a yubikey to authenticate to the google kubernetes engine.
#[derive(Clap, Debug)]
#[clap(version = "0.1")]
struct Opts {
    /// Email adress of the service account to use. This service account should have the public key of the yubikey configured as access key.
    #[clap(short, long)]
    user: String,
    #[clap(subcommand)]
    sub: SubCommand,
}

#[derive(Clap, Debug)]
enum SubCommand {
    /// Generate an identity token.
    #[clap()]
    Id,
    /// Generate an access token.
    #[clap()]
    Access,
    /// Configure kubectl for accessing the cluster.
    #[clap()]
    Config,
}

fn main() {
    let opts: Opts = Opts::parse();

    match opts.sub {
        SubCommand::Id => {
            println!("{}", get_id_token(&opts.user));
        },
        SubCommand::Access => {
            let result = get_access_token(&opts.user);
            println!("{{\"token\": \"{}\", \"expiry\": \"{}\"}}", result.0, result.1.format(Format::Rfc3339));
        }
        SubCommand::Config => {
            config::make(&opts.user);
        }
    }
}
