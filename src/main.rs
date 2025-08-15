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

const SERVERDATA_AUTH: i32 = 3;
const SERVERDATA_AUTH_RESPONSE: i32 = 2;
const SERVERDATA_EXECCOMMAND: i32 = 2;
const SERVERDATA_RESPONSE_VALUE: i32 = 0;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let stream = TcpStream::connect(args.address)?;
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);
    authenticate(&mut reader, &mut writer, args.password)?;

    let response = execute_command(&mut reader, &mut writer, args.command)?;
    println!("{}", response);

    Ok(())
}

fn write_rcon_to(
    writer: &mut impl Write,
    id: i32,
    typ: i32,
    body: impl AsRef<str>,
) -> io::Result<()> {
    let body = body.as_ref();
    let body_bytes = body.as_bytes();
    let size = size_of_val(&id) + size_of_val(&typ) + body_bytes.len() + 2;
    let bytes = [
        &(size as u32).to_le_bytes(),
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

fn read_rcon_from(reader: &mut impl Read) -> io::Result<(i32, i32, String)> {
    let mut size_buf = [0; 4];
    reader.read_exact(&mut size_buf)?;
    let size = u32::from_le_bytes(size_buf);

    let mut id_buf = [0; 4];
    reader.read_exact(&mut id_buf)?;
    let id = i32::from_le_bytes(id_buf);

    let mut typ_buf = [0; 4];
    reader.read_exact(&mut typ_buf)?;
    let typ = i32::from_le_bytes(typ_buf);

    let mut body_buf = vec![0; size as usize - 4 - 4];
    reader.read_exact(&mut body_buf)?;
    let body = String::from_utf8_lossy(&body_buf.trim_ascii_end());

    Ok((id, typ, body.into_owned()))
}

fn authenticate(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    password: impl AsRef<str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let password = password.as_ref();
    write_rcon_to(writer, 0, SERVERDATA_AUTH, password)?;
    let (id, typ, _) = read_rcon_from(reader)?;
    if typ != SERVERDATA_AUTH_RESPONSE || id > 0 {
        Err("Unmatched response".into())
    } else if id < 0 {
        Err("Authentication failed".into())
    } else {
        Ok(())
    }
}

fn execute_command(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    command: impl AsRef<str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let command = command.as_ref();
    write_rcon_to(writer, 0, SERVERDATA_EXECCOMMAND, command)?;
    let (id, typ, response) = read_rcon_from(reader)?;
    if typ != SERVERDATA_RESPONSE_VALUE || id != 0 {
        Err("Unmatched response".into())
    } else {
        Ok(response)
    }
}
