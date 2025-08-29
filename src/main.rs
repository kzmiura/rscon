use clap::Parser;
use core::panic;
use std::error::Error;
use std::io;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    address: SocketAddr,
    #[arg(short, long)]
    password: String,
}

#[derive(Debug)]
struct Response {
    id: i32,
    typ: ResponseType,
    body: String,
}

#[derive(Debug)]
enum ResponseType {
    AuthResponse = 2,
    ResponseValue = 0,
}

fn main() {
    let cli = Cli::parse();

    let stream = TcpStream::connect_timeout(&cli.address, Duration::from_secs(1))
        .expect("Couldn't connect to the server...");
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);

    authenticate(&mut reader, &mut writer, &cli.password).expect("Authentication failed...");

    let stdin = io::stdin();
    {
        let handle = stdin.lock();
        for line in handle.lines() {
            let line = line.expect("Reading line failed...");
            let command = line.trim();
            if command.is_empty() {
                continue;
            }
            let response = execute_command(&mut reader, &mut writer, command).expect("Executing command failed...");
            println!("{}", response);
        }
    }
}

fn write_rcon_to(
    writer: &mut impl Write,
    id: i32,
    typ: u32,
    body: impl AsRef<str>,
) -> io::Result<()> {
    let body = body.as_ref();
    let id_bytes = &id.to_le_bytes();
    let typ_bytes = &typ.to_le_bytes();
    let body_bytes = body.as_bytes();
    let null_bytes = b"\0\0";
    let size = size_of_val(id_bytes)
        + size_of_val(typ_bytes)
        + size_of_val(body_bytes)
        + size_of_val(null_bytes);
    let size_bytes = &(size as u32).to_le_bytes();

    for bytes in [size_bytes, id_bytes, typ_bytes, body_bytes, null_bytes] {
        writer.write_all(bytes)?;
    }
    writer.flush()?;

    Ok(())
}

fn read_rcon_from(reader: &mut impl Read) -> io::Result<Response> {
    let mut four_bytes_buf = [0; 4];
    reader.read_exact(&mut four_bytes_buf)?;
    let size = u32::from_le_bytes(four_bytes_buf);

    let mut buf = vec![0; size as usize - 2];
    reader.read_exact(&mut buf)?;
    let id = i32::from_le_bytes(buf[0..4].try_into().expect("slice should be 4 bytes"));
    let typ = u32::from_le_bytes(buf[4..8].try_into().expect("slice should be 4 bytes"));
    let body = String::from_utf8_lossy(&buf[8..]);

    // read the two null bytes
    reader.read_exact(&mut [0; 2])?;

    let typ = match typ {
        0 => ResponseType::ResponseValue,
        2 => ResponseType::AuthResponse,
        _ => panic!("unknown response type: {}", typ),
    };
    let body = body.into_owned();

    Ok(Response { id, typ, body })
}

fn authenticate(
    reader: &mut impl Read,
    writer: &mut impl Write,
    password: impl AsRef<str>,
) -> Result<(), Box<dyn Error>> {
    write_rcon_to(writer, 0, 3, password)?;
    let response = read_rcon_from(reader)?;
    match response.typ {
        ResponseType::AuthResponse => {
            if response.id == -1 {
                Err("authentication failed".into())
            } else {
                Ok(())
            }
        }
        _ => panic!("response type should be AuthResponse"),
    }
}

fn execute_command(
    reader: &mut impl Read,
    writer: &mut impl Write,
    command: impl AsRef<str>,
) -> io::Result<String> {
    write_rcon_to(writer, 0, 2, command)?;
    // marker
    // see also: https://developer.valvesoftware.com/wiki/Source_RCON_Protocol#Multiple-packet_Responses
    write_rcon_to(writer, -1, 0, "")?;

    let mut result = String::new();
    loop {
        let response = read_rcon_from(reader)?;
        match response.typ {
            ResponseType::ResponseValue => {
                if response.id == -1 {
                    break Ok(result);
                }
                if response.id == 0 {
                    result += &response.body;
                } else {
                    panic!("response id should be match the request id");
                }
            }
            _ => panic!("response type should be ResponseValue"),
        }
    }
}
