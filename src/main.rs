use std::{fmt::Display, io::{self, Write}, str::FromStr};

use miniscript::{bitcoin::{hashes::{sha256d, Hash}, key::Secp256k1, secp256k1::SecretKey, Network, PrivateKey, PublicKey}, descriptor::{DescriptorSecretKey, SinglePub, SinglePubKey}, DescriptorPublicKey};

const NAME_BYTE: u8 = 0x00;
const DESCRIPTION_BYTE: u8 = 0x01;
const RECOVERY_HEIGHT_BYTE: u8 = 0x02;
const PUBDESC_BYTE: u8 = 0x03;
const PRIVDESC_BYTE: u8 = 0x04;

#[allow(dead_code)]
#[derive(Debug)]
enum Record {
    Name(String),
    Description(String),
    RecoveryHeight(u32),
    PublicDescriptor(DescriptorPublicKey),
    PrivateDescriptor(DescriptorSecretKey),
}

impl Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Record::Name(name) => {
                write!(f, "Wallet name: {name}")
            },
            Record::Description(description) => {
                write!(f, "Wallet description: {description}")
            },
            Record::RecoveryHeight(height) => {
                write!(f, "Height to fully recover the wallet: {height}")
            },
            Record::PublicDescriptor(desc) => {
                write!(f, "Descriptor public key: {desc}")
            },
            Record::PrivateDescriptor(_) => {
                write!(f, "Private Descriptors are not displayed.")
            },
        }
    }
}

impl Record {
    fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        let bytes = match self {
            // `as_bytes` encodes the string as a UTF-8 byte array
            Record::Name(name) => {
                let byte_encoding = name.as_bytes();
                let mut buf = Self::encode_message(NAME_BYTE, byte_encoding)?;
                let checksum = Self::calc_checksum(NAME_BYTE, byte_encoding);
                buf.extend(&checksum);
                buf
            },
            Record::Description(description) => {
                let byte_encoding = description.as_bytes();
                let mut buf = Self::encode_message(DESCRIPTION_BYTE, byte_encoding)?;
                let checksum = Self::calc_checksum(DESCRIPTION_BYTE, byte_encoding);
                buf.extend(&checksum);
                buf

            },
            Record::RecoveryHeight(height) => {
                let height_bytes = height.to_le_bytes();
                let len: u16 = 4;
                buf.push(RECOVERY_HEIGHT_BYTE);
                buf.extend(len.to_le_bytes());
                buf.extend(height_bytes);
                let checksum = Self::calc_checksum(RECOVERY_HEIGHT_BYTE, &height_bytes);
                buf.extend(&checksum);
                buf
            },
            Record::PublicDescriptor(pub_desc) => {
                let string_encoding = pub_desc.to_string();
                let byte_encoding = string_encoding.as_bytes(); 
                let mut buf = Self::encode_message(PUBDESC_BYTE, byte_encoding)?;
                let checksum = Self::calc_checksum(PUBDESC_BYTE, byte_encoding);
                buf.extend(&checksum);
                buf
            },
            Record::PrivateDescriptor(priv_desc) => {
                let string_encoding = priv_desc.to_string();
                let byte_encoding = string_encoding.as_bytes();
                let mut buf = Self::encode_message(PRIVDESC_BYTE, byte_encoding)?;
                let checksum = Self::calc_checksum(PRIVDESC_BYTE, byte_encoding);
                buf.extend(&checksum);
                buf

            },
        };
        Ok(bytes)
    }

    fn encode_message(message_type: u8, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        let len: u16 = message.len().try_into().map_err(|_| Error::RecordLengthOverflow)?;
        // Type
        buf.extend_from_slice(&message_type.to_le_bytes());
        // Length
        buf.extend(len.to_le_bytes());
        // Value
        buf.extend(message);
        Ok(buf)
    }

    fn calc_checksum(message_type: u8, message: &[u8]) -> [u8; 4] {
        let mut hash_buf = Vec::new();
        // Commit the message type and message
        hash_buf.extend_from_slice(&message_type.to_le_bytes());
        hash_buf.extend(message);
        let hash = sha256d::Hash::hash(&hash_buf);
        let checksum: [u8; 4] = hash.to_byte_array()[..4].try_into().unwrap();
        checksum
    }   
}

fn encode_records(records: Vec<Record>) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let len: u8 = records.len().try_into().map_err(|_| Error::RecordCountOverflow)?;
    buf.extend_from_slice(&len.to_le_bytes());
    for record in records {
        buf.extend(&record.encode()?)
    }
    Ok(buf)

}

fn decode_records(mut reader: impl io::Read + Send + Sync) -> Result<Vec<Record>, Error> {
    let mut records = Vec::new();
    // The first byte commits to the length
    let mut len_byte = [0; 1];
    reader.read_exact(&mut len_byte).map_err(|_| Error::UnexpectedEOF)?;
    let len = u8::from_le_bytes(len_byte);
    let mut record_count = 0;
    while record_count < len {
        // Read off the message type
        let mut message_byte = [0; 1];
        reader.read_exact(&mut message_byte).map_err(|_| Error::UnexpectedEOF)?;
        let message_byte = u8::from_le_bytes(message_byte);
        // Next two bytes are the record length
        let mut record_len = [0; 2];
        reader.read_exact(&mut record_len).map_err(|_| Error::UnexpectedEOF)?;
        let record_len = u16::from_le_bytes(record_len);
        // Read the variable-length message
        let mut record_buf = vec![0; record_len as usize];
        reader.read_exact(&mut record_buf).map_err(|_| Error::UnexpectedEOF)?;
        // Calculate and validate the checksum by reading an additional four bytes
        let checksum = Record::calc_checksum(message_byte, &record_buf);
        let mut file_checksum = [0; 4];
        reader.read_exact(&mut file_checksum).map_err(|_| Error::UnexpectedEOF)?;
        if checksum.ne(&file_checksum) {
            return Err(Error::InvalidChecksum)
        }
        // All strings are encoded as UTF8 and should be parsed as such
        let record = match message_byte {
            NAME_BYTE => {
                Record::Name(String::from_utf8(record_buf).map_err(|_| Error::InvalidUTF8)?)
            },
            DESCRIPTION_BYTE => {
                Record::Description(String::from_utf8(record_buf).map_err(|_| Error::InvalidUTF8)?)
            },
            RECOVERY_HEIGHT_BYTE => {
                let height: u32 = u32::from_le_bytes(record_buf.try_into().map_err(|_| Error::InvalidHeightEncoding)?);
                Record::RecoveryHeight(height)
            },
            PUBDESC_BYTE => {
                let desc_string = String::from_utf8(record_buf).map_err(|_| Error::InvalidUTF8)?;
                let desc = DescriptorPublicKey::from_str(&desc_string).map_err(|_| Error::InvalidDescriptor)?;
                Record::PublicDescriptor(desc)
            },
            PRIVDESC_BYTE => {
                let desc_string = String::from_utf8(record_buf).map_err(|_| Error::InvalidUTF8)?;
                let desc = DescriptorSecretKey::from_str(&desc_string).map_err(|_| Error::InvalidDescriptor)?;
                Record::PrivateDescriptor(desc)
            },
            _ => return Err(Error::UnknownMessageType)
        };
        records.push(record);
        record_count += 1;
    }
    Ok(records)
}

#[derive(Debug)]
enum Error {
    RecordCountOverflow,
    RecordLengthOverflow,
    UnexpectedEOF,
    UnknownMessageType,
    InvalidChecksum,
    InvalidUTF8,
    InvalidHeightEncoding,
    InvalidDescriptor,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::RecordCountOverflow => write!(f, "the number of records was too large."),
            Error::RecordLengthOverflow => write!(f, "the length of the data was too large."),
            Error::UnexpectedEOF => write!(f, "unexpected end of file."),
            Error::UnknownMessageType => write!(f, "unrecognized message type encoding."),
            Error::InvalidChecksum => write!(f, "the checksum present in the file does not match the calculated checksum."),
            Error::InvalidUTF8 => write!(f, "the record could not be decoded into a string with UTF-8."),
            Error::InvalidHeightEncoding => write!(f, "the height could not be fit into a 4 byte slice."),
            Error::InvalidDescriptor => write!(f, "the descriptor could not be parsed."),
        }
    }
}

impl std::error::Error for Error {}

fn main() {
    // Wallet metadata
    let name = Record::Name("My wallet".into());
    let description = Record::Description("Very important description".into());
    let height = Record::RecoveryHeight(840_000);
    // Generate a key
    let secret = SecretKey::from_slice(&[0xCD; 32]).unwrap();
    let priv_key = PrivateKey::new(secret, Network::Regtest);
    let pub_key = PublicKey::from_private_key(&Secp256k1::new(), &priv_key);
    let desc_pub = DescriptorPublicKey::Single(SinglePub { origin: None, key: SinglePubKey::FullKey(pub_key) });
    // Add the key as a record
    let desc_record = Record::PublicDescriptor(desc_pub);
    // Write the records to a file
    let records = vec![name, description, height, desc_record];
    let buf = encode_records(records).unwrap();
    let file = std::fs::File::create("my_wallet.wdef").unwrap();
    let mut writer = std::io::BufWriter::new(&file);
    writer.write_all(&buf).unwrap();
    writer.flush().unwrap();
    drop(writer);
    drop(file);
    // Open the file
    let file = std::fs::File::open("my_wallet.wdef").unwrap();
    let reader = std::io::BufReader::new(&file);
    // Decode into a list of records
    let records = decode_records(reader).unwrap();
    for record in records {
        println!("{record}");
    }

}