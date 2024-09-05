use std::io::Write;

use miniscript::{
    bitcoin::{key::Secp256k1, secp256k1::SecretKey, Network, PrivateKey, PublicKey},
    descriptor::{SinglePub, SinglePubKey},
};
use wdef::{decode_records, Descriptor, DescriptorPublicKey, Import, Record};

fn main() {
    // Wallet metadata
    let name = Record::Name("My wallet".into());
    let description = Record::Description("Very important description".into());
    let info = Record::Info("Check the cubbards".into());
    let height = Record::RecoveryHeight(840_000);
    // Generate a key
    let secret = SecretKey::from_slice(&[0xCD; 32]).unwrap();
    let priv_key = PrivateKey::new(secret, Network::Regtest);
    let pub_key = PublicKey::from_private_key(&Secp256k1::new(), &priv_key);
    let desc_pub = DescriptorPublicKey::Single(SinglePub {
        origin: None,
        key: SinglePubKey::FullKey(pub_key),
    });
    let desc = Descriptor::new_pk(desc_pub);
    // Add the key as a record
    let desc_record = Record::ExternalDescriptor(desc);
    // Write the records to a file
    let records = vec![name, description, info, height, desc_record];
    let buf = Import::from_records(records).unwrap().encode();
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
    let import = decode_records(reader).unwrap();
    println!("Wallet name {}", import.name());
    for record in import.list_external_descriptors() {
        println!("External descriptor: {record}");
    }
}
