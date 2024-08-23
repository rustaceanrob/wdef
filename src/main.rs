use std::{
    fmt::Display,
    io::{self, Write},
    str::FromStr,
};

use miniscript::{
    bitcoin::{
        hashes::{sha256d, Hash},
        key::Secp256k1,
        secp256k1::SecretKey,
        Network, PrivateKey, PublicKey,
    },
    descriptor::{DescriptorSecretKey, SinglePub, SinglePubKey},
    DescriptorPublicKey,
};

/// A type of record that may be recorded in a WDEF file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordType(u8);

impl RecordType {
    /// A canonical name for the wallet.
    pub const NAME: RecordType = RecordType(0x00);
    /// A description of the wallet.
    pub const DESCRIPTION: RecordType = RecordType(0x01);
    /// The height in the chain of most work to start scanning for transactions.
    pub const RECOVERY_HEIGHT: RecordType = RecordType(0x02);
    /// A descriptor that is inheritantly safe to share.
    pub const PUB_DESC: RecordType = RecordType(0x03);
    /// A descriptor with secret information that could spend bitcoins.
    pub const PRIV_DESC: RecordType = RecordType(0x04);
}

impl From<RecordType> for u8 {
    fn from(value: RecordType) -> Self {
        value.0
    }
}

/// Records and associated content.
#[allow(dead_code)]
#[derive(Debug)]
pub enum Record {
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
            }
            Record::Description(description) => {
                write!(f, "Wallet description: {description}")
            }
            Record::RecoveryHeight(height) => {
                write!(f, "Height to fully recover the wallet: {height}")
            }
            Record::PublicDescriptor(desc) => {
                write!(f, "Descriptor public key: {desc}")
            }
            Record::PrivateDescriptor(_) => {
                write!(f, "Private Descriptors are not displayed.")
            }
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
                let mut buf = Self::encode_message(RecordType::NAME, byte_encoding)?;
                let checksum = Self::calc_checksum(RecordType::NAME, byte_encoding);
                buf.extend(&checksum);
                buf
            }
            Record::Description(description) => {
                let byte_encoding = description.as_bytes();
                let mut buf = Self::encode_message(RecordType::DESCRIPTION, byte_encoding)?;
                let checksum = Self::calc_checksum(RecordType::DESCRIPTION, byte_encoding);
                buf.extend(&checksum);
                buf
            }
            Record::RecoveryHeight(height) => {
                let height_bytes = height.to_le_bytes();
                let len: u16 = 4;
                buf.push(RecordType::RECOVERY_HEIGHT.into());
                buf.extend(len.to_le_bytes());
                buf.extend(height_bytes);
                let checksum = Self::calc_checksum(RecordType::RECOVERY_HEIGHT, &height_bytes);
                buf.extend(&checksum);
                buf
            }
            Record::PublicDescriptor(pub_desc) => {
                let string_encoding = pub_desc.to_string();
                let byte_encoding = string_encoding.as_bytes();
                let mut buf = Self::encode_message(RecordType::PUB_DESC, byte_encoding)?;
                let checksum = Self::calc_checksum(RecordType::PUB_DESC, byte_encoding);
                buf.extend(&checksum);
                buf
            }
            Record::PrivateDescriptor(priv_desc) => {
                let string_encoding = priv_desc.to_string();
                let byte_encoding = string_encoding.as_bytes();
                let mut buf = Self::encode_message(RecordType::PRIV_DESC, byte_encoding)?;
                let checksum = Self::calc_checksum(RecordType::PRIV_DESC, byte_encoding);
                buf.extend(&checksum);
                buf
            }
        };
        Ok(bytes)
    }

    fn encode_message(message_type: RecordType, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        let len: u16 = message
            .len()
            .try_into()
            .map_err(|_| Error::RecordLengthOverflow)?;
        // Type
        buf.extend_from_slice(&message_type.0.to_le_bytes());
        // Length
        buf.extend(len.to_le_bytes());
        // Value
        buf.extend(message);
        Ok(buf)
    }

    fn calc_checksum(message_type: RecordType, message: &[u8]) -> [u8; 4] {
        let mut hash_buf = Vec::new();
        // Commit the message type and message
        hash_buf.extend_from_slice(&message_type.0.to_le_bytes());
        hash_buf.extend(message);
        let hash = sha256d::Hash::hash(&hash_buf);
        let checksum: [u8; 4] = hash.to_byte_array()[..4].try_into().unwrap();
        checksum
    }
}

pub fn encode_records(records: Vec<Record>) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let len: u8 = records
        .len()
        .try_into()
        .map_err(|_| Error::RecordCountOverflow)?;
    buf.extend_from_slice(&len.to_le_bytes());
    for record in records {
        buf.extend(&record.encode()?)
    }
    Ok(buf)
}

pub fn decode_records(mut reader: impl io::Read + Send + Sync) -> Result<Vec<Record>, Error> {
    let mut records = Vec::new();
    // The first byte commits to the length
    let mut len_byte = [0; 1];
    reader
        .read_exact(&mut len_byte)
        .map_err(|_| Error::UnexpectedEOF)?;
    let len = u8::from_le_bytes(len_byte);
    let mut record_count = 0;
    while record_count < len {
        // Read off the message type
        let mut message_byte = [0; 1];
        reader
            .read_exact(&mut message_byte)
            .map_err(|_| Error::UnexpectedEOF)?;
        let message_byte = u8::from_le_bytes(message_byte);
        // Next two bytes are the record length
        let mut record_len = [0; 2];
        reader
            .read_exact(&mut record_len)
            .map_err(|_| Error::UnexpectedEOF)?;
        let record_len = u16::from_le_bytes(record_len);
        // Read the variable-length message
        let mut record_buf = vec![0; record_len as usize];
        reader
            .read_exact(&mut record_buf)
            .map_err(|_| Error::UnexpectedEOF)?;
        // Calculate and validate the checksum by reading an additional four bytes
        let checksum = Record::calc_checksum(RecordType(message_byte), &record_buf);
        let mut file_checksum = [0; 4];
        reader
            .read_exact(&mut file_checksum)
            .map_err(|_| Error::UnexpectedEOF)?;
        if checksum.ne(&file_checksum) {
            return Err(Error::InvalidChecksum);
        }
        // All strings are encoded as UTF8 and should be parsed as such
        let record = match RecordType(message_byte) {
            RecordType::NAME => {
                Record::Name(String::from_utf8(record_buf).map_err(|_| Error::InvalidUTF8)?)
            }
            RecordType::DESCRIPTION => {
                Record::Description(String::from_utf8(record_buf).map_err(|_| Error::InvalidUTF8)?)
            }
            RecordType::RECOVERY_HEIGHT => {
                let height: u32 = u32::from_le_bytes(
                    record_buf
                        .try_into()
                        .map_err(|_| Error::InvalidHeightEncoding)?,
                );
                Record::RecoveryHeight(height)
            }
            RecordType::PUB_DESC => {
                let desc_string = String::from_utf8(record_buf).map_err(|_| Error::InvalidUTF8)?;
                let desc = DescriptorPublicKey::from_str(&desc_string)
                    .map_err(|_| Error::InvalidDescriptor)?;
                Record::PublicDescriptor(desc)
            }
            RecordType::PRIV_DESC => {
                let desc_string = String::from_utf8(record_buf).map_err(|_| Error::InvalidUTF8)?;
                let desc = DescriptorSecretKey::from_str(&desc_string)
                    .map_err(|_| Error::InvalidDescriptor)?;
                Record::PrivateDescriptor(desc)
            }
            _ => return Err(Error::UnknownMessageType),
        };
        records.push(record);
        record_count += 1;
    }
    Ok(records)
}

#[derive(Debug)]
pub enum Error {
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
            Error::InvalidChecksum => write!(
                f,
                "the checksum present in the file does not match the calculated checksum."
            ),
            Error::InvalidUTF8 => write!(
                f,
                "the record could not be decoded into a string with UTF-8."
            ),
            Error::InvalidHeightEncoding => {
                write!(f, "the height could not be fit into a 4 byte slice.")
            }
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
    let desc_pub = DescriptorPublicKey::Single(SinglePub {
        origin: None,
        key: SinglePubKey::FullKey(pub_key),
    });
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