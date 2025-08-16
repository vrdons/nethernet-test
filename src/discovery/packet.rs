use byteorder::{ReadBytesExt, WriteBytesExt};

pub trait Packet {
    fn id(&self) -> u16;
    fn write(&self, w: &mut Vec<u8>);
    fn read(&mut self, r: &mut dyn std::io::Read);
}

#[derive(Debug, Clone)]
pub struct Header {
    pub packet_id: u16,
    pub sender_id: u64,
}

impl Header {
    pub fn new(packet_id: u16, sender_id: u64) -> Self {
        Header {
            packet_id,
            sender_id,
        }
    }

    pub fn read(r: &mut dyn std::io::Read) -> Result<Self, std::io::Error> {
        let packet_id = r.read_u16::<byteorder::LittleEndian>()?;
        let sender_id = r.read_u64::<byteorder::LittleEndian>()?;

        let mut padding = [0u8; 8];
        r.read_exact(&mut padding)?;

        Ok(Header {
            packet_id,
            sender_id,
        })
    }

    pub fn write(&self, w: &mut dyn std::io::Write) -> Result<(), std::io::Error> {
        w.write_u16::<byteorder::LittleEndian>(self.packet_id)?;
        w.write_u64::<byteorder::LittleEndian>(self.sender_id)?;
        w.write_all(&[0u8; 8])?;
        Ok(())
    }
}

pub fn encrypt(packet: &dyn Packet, sender_id: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    let header = Header {
        packet_id: packet.id(),
        sender_id,
    };
    header.write(&mut buf).unwrap();
    packet.write(&mut buf);

    let mut payload = Vec::new();
    payload
        .write_u16::<byteorder::LittleEndian>(buf.len() as u16)
        .unwrap();
    payload.extend_from_slice(&buf);

    let encrypted = super::crypto::encrypt(&payload);

    let hmac = super::crypto::hmac_sha256(&payload);

    let mut result = Vec::new();
    result.extend_from_slice(&hmac);
    result.extend_from_slice(&encrypted);

    result
}
pub fn decrypt(packet: &[u8]) -> Result<(std::io::Cursor<Vec<u8>>, Header), std::io::Error> {
    if packet.len() < 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Packet too short",
        ));
    }
    let payload = super::crypto::decrypt(&packet[32..])?;
    super::crypto::checksum(&payload, &packet[..32])?;
    let mut cursor = std::io::Cursor::new(payload);
    let _length = cursor.read_u16::<byteorder::LittleEndian>().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("read length prefix: {}", e),
        )
    })?;

    let header = Header::read(&mut cursor).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("read header: {}", e),
        )
    })?;
    Ok((cursor, header))
}
pub fn read_bytes_u8(r: &mut impl std::io::Read) -> Result<Vec<u8>, std::io::Error> {
    let length = r.read_u8()? as usize;
    let mut buf = vec![0u8; length];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn read_bytes_u32(r: &mut impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let length = r.read_u32::<byteorder::LittleEndian>()? as usize;
    let mut buf = vec![0u8; length];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn write_bytes_u8(w: &mut impl std::io::Write, b: &[u8]) -> Result<(), std::io::Error> {
    w.write_all(&[b.len() as u8])?;
    w.write_all(b)?;
    Ok(())
}

pub fn write_bytes_u32(w: &mut impl std::io::Write, b: &[u8]) -> Result<(), std::io::Error> {
    w.write_u32::<byteorder::LittleEndian>(b.len() as u32)?;
    w.write_all(b)?;
    Ok(())
}
pub fn write_bytes<L>(w: &mut impl std::io::Write, b: &[u8]) -> Result<(), std::io::Error>
where
    L: byteorder::ByteOrder + From<u8> + Into<usize> + Copy,
{
    match std::mem::size_of::<L>() {
        1 => w.write_all(&[L::from(b.len() as u8).into() as u8])?,
        4 => w.write_u32::<byteorder::LittleEndian>(b.len() as u32)?,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unsupported type",
            ));
        }
    }
    w.write_all(b)?;
    Ok(())
}
