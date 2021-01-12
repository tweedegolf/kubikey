use std::process;

use clap::Clap;

mod yubikey;
use yubikey::YubiKey;
use signature::Signer;

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

fn main() {
    let opts: Opts = Opts::parse();

    match opts.sub {
        SubCommand::Sign => {
            let mut yubikey = YubiKey::open().unwrap_or_else(|error| {
                println!("Unable to reach yubikey ({:?})", error);
                process::exit(1);
            });
        
            yubikey.verify_pin_from_tty().expect("Failed pin check");
        
            let data: Vec<u8> = vec![3,1,2,5,7,9,1];
            let res = yubikey.sign(&data);
            println!("{:?}", res);
        },
    }
}
