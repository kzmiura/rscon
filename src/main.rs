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

    let mut buffer = String::new();
    let stdin = io::stdin();
    {
        let mut handle = stdin.lock();
        while handle.read_line(&mut buffer)? > 0 {
            let command = buffer.trim();
            if command.is_empty() {
                continue;
            }
            let response = execute_command(&mut reader, &mut writer, command)?;
            print!("{}", response);
            buffer.clear();
        }
    }

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

    let mut body_buf = vec![0; size as usize - 4 - 4 - 2];
    reader.read_exact(&mut body_buf)?;
    let body = String::from_utf8_lossy(&body_buf);
    reader.read_exact(&mut [0; 2])?;

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
    if typ != SERVERDATA_AUTH_RESPONSE {
        Err("Unexpected response type".into())
    } else {
        match id {
            0 => Ok(()),
            -1 => Err("Authentication failed".into()),
            _ => Err("Unmatched response id".into()),
        }
    }
}

fn execute_command(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    command: impl AsRef<str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let command = command.as_ref();
    write_rcon_to(writer, 0, SERVERDATA_EXECCOMMAND, command)?;
    write_rcon_to(writer, -1, SERVERDATA_RESPONSE_VALUE, "")?;

    let mut response = String::new();
    loop {
        let (id, typ, body) = read_rcon_from(reader)?;
        if typ != SERVERDATA_RESPONSE_VALUE {
            return Err("Unexpected response type".into());
        }
        if id == -1 {
            break;
        }
        response += &body;
    }

    Ok(response)
}
