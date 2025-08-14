use std::io::prelude::*;
use std::io::{self, BufReader, BufWriter};
use std::net::{SocketAddr, TcpStream};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    address: SocketAddr,
    #[arg(short, long)]
    password: String,
    #[arg(short, long)]
    command: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let stream = TcpStream::connect(args.address)?;
    authenticate(&stream, args.password)?;
    let response = execute_command(&stream, args.command)?;
    println!("{}", response);

    Ok(())
}

fn write_rcon_to(
    writer: &mut impl Write,
    id: i32,
    typ: i32,
    body: impl AsRef<str>,
) -> Result<(), io::Error> {
    let body = body.as_ref();
    let body_bytes = body.as_bytes();
    let size = (size_of_val(&id) + size_of_val(&typ) + body_bytes.len() + 2) as u32;
    let bytes = [
        &size.to_le_bytes(),
        &id.to_le_bytes(),
        &typ.to_le_bytes(),
        body_bytes,
        &[0; 2],
    ]
    .concat();
    writer.write_all(&bytes)?;
    writer.flush()?;

    Ok(())
}

fn authenticate(
    stream: &TcpStream,
    password: impl AsRef<str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(stream);
    let mut writer = BufWriter::new(stream);
    let id = 0;
    let typ = 3;
    let password = password.as_ref();
    write_rcon_to(&mut writer, id, typ, password)?;

    let mut size_buf = [0; 4];
    reader.read_exact(&mut size_buf)?;
    let size = u32::from_le_bytes(size_buf);
    let mut buf = vec![0; size as usize];
    reader.read_exact(&mut buf)?;
    let (id, typ, _) = parse_packet(size, &buf)?;

    if typ != 2 || id != 0 {
        Err("Unmatched response".into())
    } else if id == -1 {
        Err("Authentication failed".into())
    } else {
        Ok(())
    }
}

fn execute_command(
    stream: &TcpStream,
    command: impl AsRef<str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(stream);
    let mut writer = BufWriter::new(stream);
    let id = 0;
    let typ = 2;
    let command = command.as_ref();
    write_rcon_to(&mut writer, id, typ, command)?;

    let mut size_buf = [0; 4];
    reader.read_exact(&mut size_buf)?;
    let size = u32::from_le_bytes(size_buf);
    let mut buf = vec![0; size as usize];
    reader.read_exact(&mut buf)?;
    let (id, typ, body) = parse_packet(size, &buf)?;
    
    if typ != 0 || id != 0 {
        Err("Unmatched response".into())
    } else {
        Ok(body)
    }
}

fn parse_packet(size: u32, mut bytes: &[u8]) -> Result<(i32, i32, String), io::Error> {
    let mut buf = [0; 4];
    bytes.read_exact(&mut buf)?;
    let id = i32::from_le_bytes(buf);
    bytes.read_exact(&mut buf)?;
    let typ = i32::from_le_bytes(buf);
    let body = String::from_utf8_lossy(&bytes[..size as usize - 10]);

    Ok((id, typ, body.into_owned()))
}
