use io::IsTerminal;
use io::prelude::*;
use std::io;
use std::net::TcpStream;
use std::process::ExitCode;

use rscon::RconClient;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    host: String,
    port: u16,
    #[arg(short, long)]
    password: String,
}

fn main() -> ExitCode {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("{e}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn run(cli: Cli) -> io::Result<()> {
    let Cli {
        host,
        port,
        password,
    } = cli;
    let stream = TcpStream::connect((host, port))?;
    let mut client = RconClient::new(&stream)?;
    if !client.authenticate(&password)? {
        eprintln!("Authentication failed");
    } else {
        let mut buf = String::new();
        loop {
            buf.clear();
            if io::stdout().is_terminal() {
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
    }

    Ok(())
}
