use std::process;

use clap::Clap;

mod yubikey;
use yubikey::YubiKey;
use signature::Signer;
use serde::Serialize;

#[derive(Clap, Debug)]
#[clap(version = "0.1")]
struct Opts {
    #[clap(subcommand)]
    sub: SubCommand,
}

#[derive(Clap, Debug)]
enum SubCommand {
    #[clap()]
    Sign,
}

#[derive(Serialize)]
struct JWTHeader {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Serialize)]
struct Claims {
    iat: i64,
    exp: i64,
}

fn main() {
    let opts: Opts = Opts::parse();

    match opts.sub {
        SubCommand::Sign => {
            let mut yubikey = YubiKey::open().unwrap_or_else(|error| {
                println!("Unable to reach yubikey ({:?})", error);
                process::exit(1);
            });
            yubikey.verify_pin_from_tty().expect("Failed pin check");

            let header = JWTHeader{
                alg: String::from("RS256"),
                typ: String::from("JWT"),
                kid: String::from(""),
            };

            let encoded_header = base64::encode_config(serde_json::to_string(&header).unwrap(), base64::URL_SAFE_NO_PAD);

            let claim = Claims {
                iat: 5,
                exp: 3605,
            };

            let encoded_claim = base64::encode_config(serde_json::to_string(&claim).unwrap(), base64::URL_SAFE_NO_PAD);

            let jwt_signature_input = format!("{}.{}", &encoded_header, &encoded_claim);
        
            let res = yubikey.sign(jwt_signature_input.as_bytes());
            println!("{}.{}.{}", &encoded_header, &encoded_claim, base64::encode_config(res, base64::URL_SAFE_NO_PAD));
        },
    }
}
