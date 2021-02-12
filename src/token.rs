use std::process;

use super::yubikey::YubiKey;
use serde::{Deserialize, Serialize};
use signature::Signer;
use time::{Duration, OffsetDateTime};

// JWT header for identity tokens
#[derive(Serialize)]
struct JWTHeader {
    alg: String,
    typ: String,
}

// Claims for identity tokens
#[derive(Serialize)]
struct Claims {
    iss: String,
    aud: String,
    scope: String,
    iat: i64,
    exp: i64,
}

// TokenRequest as expected by the google oAuth2 server
#[derive(Serialize)]
struct TokenRequest {
    grant_type: String,
    assertion: String,
}

// Google oAuth2 access token response
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

// Get a yubikey-signed id token for the given user
pub fn get_id_token(user: &str) -> String {
    let mut yubikey = YubiKey::open().unwrap_or_else(|error| {
        println!("Unable to reach yubikey ({:?})", error);
        process::exit(1);
    });
    yubikey.verify_pin_from_tty().expect("Failed pin check");

    let header = JWTHeader {
        alg: String::from("RS256"),
        typ: String::from("JWT"),
    };

    let encoded_header = base64::encode_config(
        serde_json::to_string(&header).unwrap(),
        base64::URL_SAFE_NO_PAD,
    );

    let claim = Claims {
        iss: user.to_string(),
        aud: "https://oauth2.googleapis.com/token".to_string(),
        scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
        iat: OffsetDateTime::now_utc().unix_timestamp(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 5 * 60,
    };

    let encoded_claim = base64::encode_config(
        serde_json::to_string(&claim).unwrap(),
        base64::URL_SAFE_NO_PAD,
    );

    let jwt_signature_input = format!("{}.{}", &encoded_header, &encoded_claim);

    let sig = yubikey.sign(jwt_signature_input.as_bytes());
    return format!(
        "{}.{}.{}",
        &encoded_header,
        &encoded_claim,
        base64::encode_config(sig, base64::URL_SAFE_NO_PAD)
    );
}

// Request an access token (using a yubikey-signed id token) from the google oAuth provider
pub fn get_access_token(user: &str) -> (String, OffsetDateTime) {
    let request = TokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
        assertion: get_id_token(user),
    };
    let client = reqwest::blocking::Client::new();
    let response = client
        .post("https://oauth2.googleapis.com/token")
        .json(&request)
        .send()
        .expect("Could not fetch access token");
    let result = response
        .json::<TokenResponse>()
        .expect("Could not fetch access token");
    (
        result.access_token,
        OffsetDateTime::now_utc() + Duration::new(result.expires_in, 0),
    )
}
