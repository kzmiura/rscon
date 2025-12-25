use io::IsTerminal;
use io::prelude::*;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;

use rscon::RconClient;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    addr: SocketAddr,
    #[arg(short, long)]
    password: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{}", e);
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> io::Result<ExitCode> {
    let Cli { addr, password } = cli;
    let stream = TcpStream::connect(addr)?;
    let mut client = RconClient::new(&stream)?;
    let code = if !client.authenticate(&password)? {
        eprintln!("Authentication failed");
        ExitCode::FAILURE
    } else {
        let mut buf = String::new();
        loop {
            buf.clear();
            if io::stdin().is_terminal() {
                print!(">>> ");
                io::stdout().flush()?;
            }
            if io::stdin().read_line(&mut buf)? == 0 {
                break;
            }

            let command = buf.trim_end();
            let resp = client.execute_command(command)?;
            println!("{}", resp);
        }
        ExitCode::SUCCESS
    };
    Ok(code)
}
