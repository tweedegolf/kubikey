use time::Format;
use clap::Clap;

use token::{get_id_token, get_access_token};

mod token;
mod yubikey;


#[derive(Clap, Debug)]
#[clap(version = "0.1")]
struct Opts {
    #[clap(short, long)]
    user: String,
    #[clap(subcommand)]
    sub: SubCommand,
}

#[derive(Clap, Debug)]
enum SubCommand {
    #[clap()]
    Id,
    #[clap()]
    Access,
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
    }
}
