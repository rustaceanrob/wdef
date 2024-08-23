### About/Abstract

Wallet descriptor export format (WDEF) is a proposal for a standard file format to export and import descriptor-based Bitcoin wallets. The details of the specification are outlined below.

### Motivation

The purpose of a standarized file format is to decrease the chance of loss of funds in the case of wallet recovery or inheritance. BIP32 seed phrases are not sufficient information to recover a wallet if multiple signers are used, a non-standard derivation path is used, or if the recoveree does not know what to do with such seed phrase. A unified file format allows for "one-click" backups and recoveries for descriptor-based bitcoin wallets.

### Definitions

_double-SHA256_ is a hash algorithm defined by two invocations of SHA-256: `double-SHA256(x) = SHA256(SHA256(x))`. 

`||` denotes the concatenation of two elements.

`[]bytes` represents a variable array of bytes.

`[N]bytes` represents an array of `N` bytes.

`Record` is an entry in a file.

### Specification

Information is stored in a WDEF file in the form of `Record`s. A `Record` is a tuple of a `Type`, `Length`, and `Value`, followed by a 4 byte checksum. Every WDEF file is prefixed with a single byte representing the number of records in the file. A record type is represented as a byte, with possible types listed below:

| Record Type (`Type`) | Value (u8) | Description                        |
| ------------------- | ---------- | ---------------------------------- |
| Name | 0x00 | The name of the wallet in the file |
| Description | 0x01 | Summary of this wallet's use(s) |
| RecoveryHeight | 0x02 | Height in the blockchain this began to receive and send payments |
| PublicDescriptor | 0x03 | A descriptor that encodes public keys and cannot spend bitcoins |
| PrivateDescriptor | 0x03 | A descriptor that encodes secret keys and may spend bitcoins |

A length is a 16-bit number represented as bytes in _little endian_. The length represents the number of bytes in the value encoding that follows.

`Name`, `Description`, `PublicDescriptor`, and `PrivateDescriptor` are all represented as strings and encoded as the UTF-8 byte array
for such a string representation. `RecoveryHeight`s are represented as a 4 byte _little endian_ array representation.

The checksum for a `Record` is calculated by `double-SHA256( Type || Value )` and taking the first four bytes of the resulting hash.

A `Record` is completely defined as:
- `Type`: `[1]byte` ID
- `Length`: `[2]byte` _little endian_ value representing the length of the next field
- `Value`: `[]byte` variable length contents representing the record type
- Checksum: `[4] byte` a commitment to the record type and record value

#### Encoding Files

The number of records to be recorded in the file should be determined first, and if the number of records cannot fit into an 8-bit unsigned integer, encoding fails.

Next, each record is composed as `Type || Length || Value || Checksum` and concatinated together. Encoding fails if the `Length` cannot be represented as a 16-bit unsigned integer.

#### Decoding Files

The first byte is read from the file and interpreted as the number of records. For each record in the record count:

1. Read and interpret the first byte as the `Type`. Decoding fails for unrecognized `Type` values.

2. Read the next two bytes and interpret them as an 16-bit unsigned integer, denoted `L`

3. Read the next `L` bytes and parse as a UTF-8 string. Decoding fails if the bytes cannot be parsed as UTF-8.

4. Calculate the checksum using the `Value` and `Type`

5. Read the next 4 bytes and fail if the calculated and presented checksum do not match.

6. For descriptors, parse the computed string. Decoding fails for if the provided string cannot be cast to a descriptor.

### Rationale

Descriptor `Value`s are represented strings for the following reasons:

1. Bitcoin Core is supports parsing strings as descriptors within `bitcoin-cli`.

2. UTF-8 encodings are an open standard with forwards compatability for new `Type`s.

3. Most encoding logic may be shared for each `Type`.

A height is used as opposed to a block hash, as heights are human readable. 

The checksum is added to ensure that invalid `Record` encodings are discovered during decoding and file integrity is guaranteed when successfully parsing a WDEF file.