use clap::Clap;
use yubikey_piv::{Readers, key::sign_data};

#[derive(Clap, Debug)]
#[clap(version = "0.1")]
struct Opts {
    #[clap(subcommand)]
    sub: SubCommand,
}

#[derive(Clap, Debug)]
enum SubCommand {
    #[clap()]
    Init,
}

fn main() {
    let opts: Opts = Opts::parse();
    let mut readers = Readers::open()
        .expect("Could not open PC/SC context");
    let readers_iter = readers.iter()
        .expect("Could not enumerate PC/SC readers");
    if readers_iter.len() == 0 {
        println!("No yubikeys found");
    } else {
        for reader in readers_iter {
            let mut yubikey = match reader.open() {
                Ok(yk) => yk,
                Err(_) => continue,
            };
            println!("{}", yubikey.serial());

            let data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            let res = sign_data(&mut yubikey, &data, yubikey_piv::key::AlgorithmId::Rsa2048, yubikey_piv::key::SlotId::Authentication).expect("Failed signing data");
            println!("{:?}", res);
            // don't continue with any other yubikeys after we get one
            break;
        }
    }



    match opts.sub {
        SubCommand::Init => {
            println!("Init!");
        },
    }
}
