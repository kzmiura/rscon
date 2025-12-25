use io::prelude::*;
use io::{BufReader, BufWriter};
use std::io;
use std::net::TcpStream;

struct RconPacket {
    id: i32,
    typ: i32,
    body: String,
}

impl RconPacket {
    const SERVERDATA_AUTH: i32 = 3;
    const SERVERDATA_AUTH_RESPONSE: i32 = 2;
    const SERVERDATA_EXECCOMMAND: i32 = 2;
    const SERVERDATA_RESPONSE_VALUE: i32 = 0;
}

pub struct RconClient {
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
}

impl RconClient {
    pub fn new(stream: &TcpStream) -> io::Result<Self> {
        let reader = BufReader::new(stream.try_clone()?);
        let writer = BufWriter::new(stream.try_clone()?);

        Ok(Self { reader, writer })
    }

    fn read_rcon_from(&mut self) -> io::Result<RconPacket> {
        let Self { reader, .. } = self;
        let mut buf = [0; 4];
        reader.read_exact(&mut buf)?;
        let size = i32::from_le_bytes(buf);

        let mut buf = vec![0; size.try_into().unwrap()];
        reader.read_exact(&mut buf)?;
        let (id_bytes, rest) = buf
            .split_first_chunk::<4>()
            .expect("Rcon packet should have an id");
        let (typ_bytes, rest) = rest
            .split_first_chunk::<4>()
            .expect("Rcon packet should have a type");
        let (body_bytes, null_bytes) = rest
            .split_last_chunk::<2>()
            .expect("Rcon packet should have a body and two null bytes");
        assert_eq!(
            null_bytes, &[0; 2],
            "Rcon packet should end with two null bytes"
        );

        let id = i32::from_le_bytes(*id_bytes);
        let typ = i32::from_le_bytes(*typ_bytes);
        let body = str::from_utf8(body_bytes)
            .expect("Rcon packet body should be valid UTF-8")
            .to_owned();
        Ok(RconPacket { id, typ, body })
    }

    fn write_rcon_to(&mut self, packet: RconPacket) -> io::Result<()> {
        let Self { writer, .. } = self;
        let RconPacket { id, typ, body } = packet;

        let body_bytes = body.into_bytes();
        let size = i32::try_from(2 * size_of::<i32>() + body_bytes.len() + 2)
            .expect("Rcon packet size should fit in i32");

        for bytes in [
            &size.to_le_bytes()[..],
            &id.to_le_bytes()[..],
            &typ.to_le_bytes()[..],
            &body_bytes[..],
            &[0; 2],
        ] {
            writer.write_all(bytes)?;
        }
        writer.flush()?;

        Ok(())
    }

    pub fn authenticate(&mut self, password: &str) -> io::Result<bool> {
        let packet = RconPacket {
            id: 1,
            typ: RconPacket::SERVERDATA_AUTH,
            body: password.into(),
        };
        self.write_rcon_to(packet)?;
        match self.read_rcon_from()? {
            RconPacket {
                id: 1,
                typ: RconPacket::SERVERDATA_AUTH_RESPONSE,
                body: _,
            } => Ok(true),
            RconPacket {
                id: -1,
                typ: RconPacket::SERVERDATA_AUTH_RESPONSE,
                body: _,
            } => Ok(false),
            _ => panic!("Unexpected Rcon packet during authentication"),
        }
    }

    pub fn execute_command(&mut self, command: &str) -> io::Result<String> {
        let packet = RconPacket {
            id: 1,
            typ: RconPacket::SERVERDATA_EXECCOMMAND,
            body: command.into(),
        };
        self.write_rcon_to(packet)?;
        let marker = RconPacket {
            id: -1,
            typ: RconPacket::SERVERDATA_RESPONSE_VALUE,
            body: String::new(),
        };
        self.write_rcon_to(marker)?;

        let mut ret = String::new();
        loop {
            match self.read_rcon_from()? {
                RconPacket {
                    id: -1,
                    typ: RconPacket::SERVERDATA_RESPONSE_VALUE,
                    body: _,
                } => {
                    break Ok(ret);
                }
                RconPacket {
                    id: 1,
                    typ: RconPacket::SERVERDATA_RESPONSE_VALUE,
                    body,
                } => {
                    ret += &body;
                }
                _ => panic!("Unexpected Rcon packet during command execution"),
            }
        }
    }
}
