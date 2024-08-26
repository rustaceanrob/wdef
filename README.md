### About/Abstract

Wallet descriptor export format (WDEF) is a proposal for a standard file format to export and import descriptor-based Bitcoin wallets.

To run the example:
```
cargo run --example main
```

### Motivation

The purpose of a standarized file format is to decrease the chance of loss of funds in the case of wallet recovery or inheritance. BIP32 seed phrases are not sufficient information to recover funds if multiple signers are used, a non-standard derivation path is used, or if the recoverer does not know what to do with such seed phrase. Moreover, seed phrases must be entered into a device to recover wallet public keys. Output descriptors alleviate these issues, however the process of storing, exporting, and sharing descriptors is currently determined by users. A unified file format allows for "one-click" backups and recoveries for descriptor-based bitcoin wallets, transferring the responsibilities of handling descriptors from users to software.

Output descriptors are often exported, shared, and stored in `.txt` files, but other formats such as JSON are also used. This discrepancy causes developer burden, and varying formats cause uncertainty of support for parsing such data in future wallet software. If descriptor parsing from a `txt` or `json` file fails, it is up to the heir or recoverer to resolve the problem. A unifed file format for importing and exporting descriptors not only decreases developer burden, but allows for a higher degree of certainty that an heir will not have to manually "copy and paste" descriptors into future software. Files are portable, duplicable, and easily parsed by most devices. Files may also be encrypted and safely shared with attorneys, business partners, or other semi-trusted entities.

Futher still, metadata about the descriptors, such as the name of the wallet, a description of its uses, where to start scanning for ouputs, and additional information to recover signers are either encoded as a comment in the `.txt`, introducing difficulty for software to parse reliably, or fields in a JSON, introducing forward-compatiblity concerns for future wallet software. These fields are easily encoded and decoded with a standard format.

### Definitions

`||` denotes the concatenation of two elements.

`[]bytes` represents a variable array of bytes.

`[N]bytes` represents an array of `N` bytes.

`Record` is an entry in a file.

_descriptor_, shorthand for "output descriptor"

### Specification

Information is stored in a WDEF file in the form of `Record`s. A `Record` is a tuple of a `Type`, `Length`, and `Value`, followed by a 4 byte checksum. Every WDEF file is prefixed with a single byte representing the number of records in the file. A record type is represented as a byte, with possible types listed below:

| Record Type (`Type`) | Value (`u8`) | Description                        |
| ------------------- | ---------- | ---------------------------------- |
| Name | 0x00 | The name of the wallet in the file |
| Description | 0x01 | Summary of this wallet's use(s) |
| Info | 0x02 | Any additional information to recover funds |
| RecoveryHeight | 0x03 | Height in the blockchain this wallet began to receive and send payments |
| ExternalDescriptor | 0x04 | A descriptor that is used to receive bitcoins. Encodes public keys and cannot spend bitcoins |
| InternalDescriptor | 0x05 | A descriptor that is used to generate change outputs when spending bitcoins. Encodes public keys and cannot spend bitcoins |

A `Length` is a 16-bit number represented as bytes in _little endian_. The length represents the number of bytes in the value encoding that follows.

`Name`, `Description`, `Info`, and `ExternalDescriptor`, `InternalDescriptor` are all represented as strings and encoded as the UTF-8 byte array
for such a string representation. `RecoveryHeight`s are represented as a 4 byte _little endian_ array representation.

The checksum for a `Record` is calculated by `SHA256( Type || Value )` and taking the first four bytes of the resulting hash.

A `Record` is completely defined as:
- `Type`: `[1]bytes` ID
- `Length`: `[2]bytes` _little endian_ value representing the length of the next field
- `Value`: `[]bytes` variable length contents representing the record type, often a UTF-8 encoded string
- `Checksum`: `[4]bytes` a commitment to the record type and record value

#### Encoding Files

The number of records to be recorded in the file should be determined first, and the byte representing the length is added to the serialization buffer. If the number of records cannot fit into an 8-bit unsigned integer, encoding fails.

Next, each record is composed as `Type || Length || Value || Checksum`, and each array of bytes are concatinated together. Encoding fails if the `Length` cannot be represented as a 16-bit unsigned integer.

If no descriptor was present, encoding fails.

#### Decoding Files

The first byte is read from the file and interpreted as the number of records. For each record in the record count:

1. Read and interpret the first byte as the `Type`. Decoding fails for unrecognized `Type` values.

2. Read the next two bytes and interpret them as an 16-bit unsigned integer, denoted `L`

3. Read the next `L` bytes and parse into the desired representation. Decoding fails if the bytes cannot be parsed.

4. Calculate the checksum using the `Value` and `Type`

5. Read the next 4 bytes and fail if the calculated and presented checksum do not match.

6. For descriptors, parse the computed string and attempt to cast it to a descriptor that encodes public keys. Decoding fails for if the provided string cannot be cast to a public key descriptor.

If one or more descriptors are not present, decoding fails.

Files adhering to this standard should be postfixed with the `.wdef` extension.

### Rationale

Descriptor `Value`s are represented strings for the following reasons:

1. Bitcoin Core supports parsing strings as descriptors within `bitcoin-cli`.

2. UTF-8 encodings are an open standard with forwards compatability for new `Type`s.

3. Most encoding logic may be shared for each `Type`.

The checksum is added to ensure that invalid `Record` encodings are discovered during decoding and file integrity is guaranteed when successfully parsing a WDEF file.