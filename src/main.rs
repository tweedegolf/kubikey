use clap::Clap;

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

    match opts.sub {
        SubCommand::Init => {
            println!("Init!");
        },
    }
}
