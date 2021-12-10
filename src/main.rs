use clap::Parser;

use token::{get_access_token, get_id_token};

mod config;
mod token;
mod yubikey;

/// Kubikey is a tool for using a yubikey to authenticate to the google kubernetes engine.
#[derive(Parser, Debug)]
#[clap(version = "0.1")]
struct Opts {
    /// Email adress of the service account to use. This service account should have the public key of the yubikey configured as access key.
    #[clap(short, long)]
    user: String,
    #[clap(subcommand)]
    sub: SubCommand,
}

#[derive(Parser, Debug)]
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
        }
        SubCommand::Access => {
            let (token, expiry) = get_access_token(&opts.user);
            println!(
                "{{\"token\": \"{}\", \"expiry\": \"{}\"}}",
                token,
                expiry.format(&time::format_description::well_known::Rfc3339).unwrap(),
            );
        }
        SubCommand::Config => {
            config::make(&opts.user);
        }
    }
}
