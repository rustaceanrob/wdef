use core::fmt::Display;

use miniscript::bitcoin::hashes::{sha256, Hash};

pub use miniscript::{Descriptor, DescriptorPublicKey};

const PROTOCOL_VERSION: u8 = 0x00;
const FILE_MAGIC: [u8; 7] = [0x00, 0x00, 0x00, 0x57, 0x44, 0x45, 0x46];

/// A type of record that may be recorded in a WDEF file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct RecordType(u8);

impl RecordType {
    /// A canonical name for the wallet.
    const NAME: RecordType = RecordType(0x00);
    /// A description of the wallet.
    const DESCRIPTION: RecordType = RecordType(0x01);
    /// Additional information as to how to recover the wallet.
    const INFO: RecordType = RecordType(0x02);
    /// The height in the chain of most work to start scanning for transactions.
    const RECOVERY_HEIGHT: RecordType = RecordType(0x03);
    /// A descriptor that is used to receive payments.
    const EXTERNAL_DESCRIPTOR: RecordType = RecordType(0x04);
    /// A descriptor that is used to receive change when transacting.
    const INTERNAL_DESCRIPTOR: RecordType = RecordType(0x05);
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
    Info(String),
    RecoveryHeight(u32),
    ExternalDescriptor(Descriptor<DescriptorPublicKey>),
    InternalDescriptor(Descriptor<DescriptorPublicKey>),
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
            Record::Info(info) => {
                write!(f, "Additional information: {info}")
            }
            Record::RecoveryHeight(height) => {
                write!(f, "Height to fully recover the wallet: {height}")
            }
            Record::ExternalDescriptor(desc) => {
                write!(f, "Receiving descriptor: {desc}")
            }
            Record::InternalDescriptor(desc) => {
                write!(f, "Change descriptor: {desc}")
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
                let record_type = RecordType::NAME;
                let mut buf = Self::encode_message(record_type, byte_encoding)?;
                let checksum = Self::calc_checksum(record_type, byte_encoding);
                buf.extend(&checksum);
                buf
            }
            Record::Description(description) => {
                let byte_encoding = description.as_bytes();
                let record_type = RecordType::DESCRIPTION;
                let mut buf = Self::encode_message(record_type, byte_encoding)?;
                let checksum = Self::calc_checksum(record_type, byte_encoding);
                buf.extend(&checksum);
                buf
            }
            Record::Info(info) => {
                let byte_encoding = info.as_bytes();
                let record_type = RecordType::INFO;
                let mut buf = Self::encode_message(record_type, byte_encoding)?;
                let checksum = Self::calc_checksum(record_type, byte_encoding);
                buf.extend(&checksum);
                buf
            }
            Record::RecoveryHeight(height) => {
                let height_bytes = height.to_le_bytes();
                let record_type = RecordType::RECOVERY_HEIGHT;
                let len: u16 = 4;
                buf.push(record_type.into());
                buf.extend(len.to_le_bytes());
                buf.extend(height_bytes);
                let checksum = Self::calc_checksum(record_type, &height_bytes);
                buf.extend(&checksum);
                buf
            }
            Record::ExternalDescriptor(desc) => {
                let string_encoding = desc.to_string();
                let byte_encoding = string_encoding.as_bytes();
                let record_type = RecordType::EXTERNAL_DESCRIPTOR;
                let mut buf = Self::encode_message(record_type, byte_encoding)?;
                let checksum = Self::calc_checksum(record_type, byte_encoding);
                buf.extend(&checksum);
                buf
            }
            Record::InternalDescriptor(desc) => {
                let string_encoding = desc.to_string();
                let byte_encoding = string_encoding.as_bytes();
                let record_type = RecordType::INTERNAL_DESCRIPTOR;
                let mut buf = Self::encode_message(record_type, byte_encoding)?;
                let checksum = Self::calc_checksum(record_type, byte_encoding);
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
        let hash = sha256::Hash::hash(&hash_buf);
        let checksum: [u8; 4] = hash.to_byte_array()[..4].try_into().unwrap();
        checksum
    }
}

/// Encode records into a byte array.
pub fn encode_records(records: Vec<Record>) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    buf.extend(FILE_MAGIC);
    buf.extend(PROTOCOL_VERSION.to_le_bytes());
    let len: u8 = records
        .len()
        .try_into()
        .map_err(|_| Error::RecordCountOverflow)?;
    buf.extend_from_slice(&len.to_le_bytes());
    let mut has_descriptor = false;
    for record in records {
        if matches!(
            record,
            Record::InternalDescriptor(_) | Record::ExternalDescriptor(_)
        ) {
            has_descriptor = true
        }
        buf.extend(&record.encode()?)
    }
    if !has_descriptor {
        return Err(Error::NoDescriptor);
    }
    Ok(buf)
}

/// Decode a sequence of records from a file.
pub fn decode_records(mut reader: impl std::io::Read + Send + Sync) -> Result<Vec<Record>, Error> {
    let mut records = Vec::new();
    // Read and match the magic
    let mut magic = [0; 7];
    reader
        .read_exact(&mut magic)
        .map_err(|_| Error::UnexpectedEOF)?;
    if magic.ne(&FILE_MAGIC) {
        return Err(Error::IncorrectMagic);
    }
    // Read the protocol version
    let mut version = [0; 1];
    reader
        .read_exact(&mut version)
        .map_err(|_| Error::UnexpectedEOF)?;
    let version_number = u8::from_le_bytes(version);
    if version_number > 0 {
        return Err(Error::UnsupportedVersion)
    }
    // The first byte of the message commits to the length
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
            RecordType::INFO => {
                Record::Info(String::from_utf8(record_buf).map_err(|_| Error::InvalidUTF8)?)
            }
            RecordType::RECOVERY_HEIGHT => {
                let height: u32 = u32::from_le_bytes(
                    record_buf
                        .try_into()
                        .map_err(|_| Error::InvalidHeightEncoding)?,
                );
                Record::RecoveryHeight(height)
            }
            RecordType::EXTERNAL_DESCRIPTOR => {
                let desc_string = String::from_utf8(record_buf).map_err(|_| Error::InvalidUTF8)?;
                let desc = desc_string
                    .parse::<Descriptor<DescriptorPublicKey>>()
                    .map_err(|_| Error::InvalidDescriptor)?;
                Record::ExternalDescriptor(desc)
            }
            RecordType::INTERNAL_DESCRIPTOR => {
                let desc_string = String::from_utf8(record_buf).map_err(|_| Error::InvalidUTF8)?;
                let desc = desc_string
                    .parse::<Descriptor<DescriptorPublicKey>>()
                    .map_err(|_| Error::InvalidDescriptor)?;
                Record::InternalDescriptor(desc)
            }
            _ => return Err(Error::UnknownMessageType),
        };
        records.push(record);
        record_count += 1;
    }
    Ok(records)
}

/// A structured import from a vector of [`Record`].
pub struct Import {
    pub length: [u8; 2],
    pub name: Option<String>,
    pub description: Option<String>,
    pub info: Option<String>,
    pub height: Option<u32>,
    pub external: Option<Descriptor<DescriptorPublicKey>>,
    pub internal: Option<Descriptor<DescriptorPublicKey>>,
}

impl Import {
    /// Construct an import from a list of [`Record`].
    pub fn from_records(records: Vec<Record>) -> Result<Self, Error> {
        let mut import = Import::default();
        let records_len: u16 = records.len().try_into().map_err(|_| Error::RecordLengthOverflow)?;
        import.length = records_len.to_le_bytes();
        for record in records {
            match record {
                Record::Name(s) => import.name = Some(s),
                Record::Description(d) => import.description = Some(d),
                Record::Info(i) => import.info = Some(i),
                Record::RecoveryHeight(h) => import.height = Some(h),
                Record::ExternalDescriptor(e) => import.external = Some(e),
                Record::InternalDescriptor(i) => import.internal = Some(i),
            }
        }
        Ok(import)
    }
}

impl Default for Import {
    fn default() -> Self {
        Self {
            length: Default::default(),
            name: Default::default(),
            description: Default::default(),
            info: Default::default(),
            height: Default::default(),
            external: Default::default(),
            internal: Default::default(),
        }
    }
}

/// Possible errors when encoding and decoding a WDEF
#[derive(Debug)]
pub enum Error {
    /// Too many records were encoded.
    RecordCountOverflow,
    /// A record is too large to be encoded.
    RecordLengthOverflow,
    /// The end of the file was reached before decoding finished.
    UnexpectedEOF,
    /// A message type present in the file was not recognized.
    UnknownMessageType,
    /// A checksum present in the file did not match what was computed.
    InvalidChecksum,
    /// An encoding could not be parsed as UTF-8.
    InvalidUTF8,
    /// A height could not be parsed into 16-bits.
    InvalidHeightEncoding,
    /// A string did not parse into a descriptor properly.
    InvalidDescriptor,
    /// A string did not parse into a descriptor properly.
    NoDescriptor,
    /// The file signature is incorrect
    IncorrectMagic,
    /// The version was correctly parsed, but the current software does not support it.
    UnsupportedVersion,
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
            Error::NoDescriptor => write!(f, "no descriptor was present in the file."),
            Error::IncorrectMagic => write!(f, "the file magic was not correct."),
            Error::UnsupportedVersion => write!(f, "the version was correctly parsed, but the current software does not support it."),
        }
    }
}

impl std::error::Error for Error {}
