use std::{process, time::UNIX_EPOCH};

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
    Id,
    #[clap()]
    Access,
}

#[derive(Serialize)]
struct JWTHeader {
    alg: String,
    typ: String,
}

#[derive(Serialize)]
struct Claims {
    iss: String,
    aud: String,
    scope: String,
    iat: i64,
    exp: i64,
}

#[derive(Serialize)]
struct TokenRequest {
    grant_type: String,
    assertion: String,
}

fn get_id_token() -> String {
    let mut yubikey = YubiKey::open().unwrap_or_else(|error| {
        println!("Unable to reach yubikey ({:?})", error);
        process::exit(1);
    });
    yubikey.verify_pin_from_tty().expect("Failed pin check");

    let header = JWTHeader{
        alg: String::from("RS256"),
        typ: String::from("JWT"),
    };

    let encoded_header = base64::encode_config(serde_json::to_string(&header).unwrap(), base64::URL_SAFE_NO_PAD);

    let claim = Claims {
        iss: "david-820@tweedegolf-cluster.iam.gserviceaccount.com".to_string(),
        aud: "https://oauth2.googleapis.com/token".to_string(),
        scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
        iat: std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
        exp: (std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()+(5*60)) as i64 ,
    };

    let encoded_claim = base64::encode_config(serde_json::to_string(&claim).unwrap(), base64::URL_SAFE_NO_PAD);

    let jwt_signature_input = format!("{}.{}", &encoded_header, &encoded_claim);

    let sig = yubikey.sign(jwt_signature_input.as_bytes());
    return format!("{}.{}.{}", &encoded_header, &encoded_claim, base64::encode_config(sig, base64::URL_SAFE_NO_PAD));
}

fn get_access_token() -> String {
    let request = TokenRequest{
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
        assertion: get_id_token(),
    };
    let client = reqwest::blocking::Client::new();
    let res = client.post("https://oauth2.googleapis.com/token")
        .json(&request)
        .send().expect("Could not fetch access token");
    return res.text().expect("Could not fetch access token");
}

fn main() {
    let opts: Opts = Opts::parse();

    match opts.sub {
        SubCommand::Id => {
            println!("{}", get_id_token());
        },
        SubCommand::Access => {
            println!("{}", get_access_token());
        }
    }
}
