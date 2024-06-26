use core::convert::TryFrom;
use ed448_rust::{PrivateKey, PublicKey};
use pyo3::prelude::*;
use sodiumoxide::crypto::pwhash::{self, Salt, MEMLIMIT_INTERACTIVE, OPSLIMIT_INTERACTIVE};
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::{self, Nonce, Key};
use std::fs;
use serde::{Deserialize, Serialize};
use rmp_serde::{Deserializer, Serializer};
use std::io::{Cursor, Read};
use byteorder::{BigEndian, ReadBytesExt};

#[pyclass]
struct PastelSigner {
    private_key: PrivateKey,
}

#[derive(Serialize, Deserialize, Debug)]
struct PublicItem {
    #[serde(rename = "type")]
    item_type: String,
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SecureItem {
    #[serde(rename = "type")]
    item_type: String,
    nonce: Vec<u8>,
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SecureContainer {
    version: Option<u16>,
    timestamp: Option<i64>,
    encryption: Option<String>,
    secure_items: Vec<SecureItem>,
}

impl Default for SecureContainer {
    fn default() -> Self {
        SecureContainer {
            version: None,
            timestamp: None,
            encryption: None,
            secure_items: Vec::new(),
        }
    }
}

#[pymethods]
impl PastelSigner {
    #[new]
    fn new() -> Self {
        sodiumoxide::init().expect("Failed to initialize sodiumoxide");

        // Read the configuration file
        let settings = config::Config::builder()
            .add_source(config::File::with_name("config"))
            .build()
            .expect("Failed to read config file");

        let file_path: String = settings.get_string("pastelid.file_path").expect("Missing file_path key");
        let passphrase: String = settings.get_string("pastelid.passphrase").expect("Missing passphrase key");

        println!("Secure container file path: {}", file_path);

        // Read the SecureContainer file
        let encrypted_data = fs::read(&file_path).expect("Failed to read file");

        // Verify file header
        let header = b"PastelSecureContainer";
        if &encrypted_data[..header.len()] != header {
            panic!("Invalid file header");
        }
        println!("Valid file header");

        // Skip the header and extract the rest of the data
        let encrypted_data = &encrypted_data[header.len()..];

        // Read public items size and hash
        let mut cursor = Cursor::new(encrypted_data);
        let msgpack_public_items_size = cursor.read_u64::<BigEndian>().expect("Failed to read public items size");
        let mut public_items_hash = [0u8; 32];
        cursor.read_exact(&mut public_items_hash).expect("Failed to read public items hash");

        println!("Public items size: {}", msgpack_public_items_size);
        println!("Public items hash: {:?}", public_items_hash);

        // Deserialize the secure items
        let secure_container: SecureContainer = match rmp_serde::from_read(&mut cursor) {
            Ok(container) => container,
            Err(e) => {
                println!("Failed to deserialize secure container: {:?}", e);
                panic!("Deserialization error");
            }
        };

        println!("Deserialized secure container: {:?}", secure_container);

        // Extract the private key from the secure container
        let secure_item = secure_container.secure_items
            .iter()
            .find(|item| item.item_type == "pkey_ed448")
            .expect("Private key not found in the secure container");

        let private_key_data = &secure_item.data;
        let nonce_slice = &secure_item.nonce;

        if nonce_slice.len() != xchacha20poly1305_ietf::NONCEBYTES {
            panic!("Invalid nonce length: expected {}, got {}", xchacha20poly1305_ietf::NONCEBYTES, nonce_slice.len());
        }
        println!("Nonce slice: {:?}", nonce_slice);

        let nonce = Nonce::from_slice(&nonce_slice).expect("Failed to create nonce");

        // Derive a key from the passphrase using libsodium's crypto_pwhash
        let salt = Salt::from_slice(&nonce_slice).expect("Failed to create salt from nonce slice");

        let mut key = [0u8; xchacha20poly1305_ietf::KEYBYTES];
        pwhash::derive_key(
            &mut key,
            passphrase.as_bytes(),
            &salt,
            OPSLIMIT_INTERACTIVE,
            MEMLIMIT_INTERACTIVE
        ).expect("Failed to derive key");

        println!("Derived key: {:?}", key);

        // Decrypt the private key data using the passphrase-derived key
        let decrypted_private_key_data = match xchacha20poly1305_ietf::open(
            &private_key_data,
            None,
            &nonce,
            &Key::from_slice(&key).unwrap()
        ) {
            Ok(data) => data,
            Err(_) => {
                println!("Failed to decrypt the data. Key: {:?}, Nonce: {:?}", key, nonce_slice);
                panic!("Failed to decrypt");
            }
        };

        let private_key = PrivateKey::try_from(&decrypted_private_key_data[..]).expect("Failed to create PrivateKey");

        PastelSigner { private_key }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.private_key.sign(message, None).expect("Failed to sign");
        signature.to_vec()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let public_key = PublicKey::from(&self.private_key);
        public_key.verify(message, signature, None).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_sign_and_verify() {
        let signer = PastelSigner::new();

        let message1 = "my_message_1__hello_friends".as_bytes();
        let signature1 = signer.sign(message1);
        assert_eq!(
            hex::encode(&signature1),
            "XUrsiNwSHkgacI1iRcUkC+G82dIkEgVvhzUD1awhICkvqBGUgKho7dAWpwKUhNctRJpayS4F89qAS58urukEYs2l9hPYocK/o6gGlZ3kihkzTf7lYC+dC7VAiShiJmJM85t6GjZ3saA6jxIk/BXgqjgA"
        );
        assert!(signer.verify(message1, &signature1));

        let message2 = "my_message_2__hello_friends".as_bytes();
        let signature2 = signer.sign(message2);
        assert_eq!(
            hex::encode(&signature2),
            "CEnpEHHxenDkY6/4oOLyhqjt5Y646OKN9JJXOhOz8qWxCC6D/qrDlEeDYQlYhvRgCQKQUbSGkdQAhEXjGPaNv6oWbTO7CLF9RLHeoLGhx5SFHF0L9WVK021G48MolJJqdSdSjUaiVK8bLJlpXzbgTikA"
        );
        assert!(signer.verify(message2, &signature2));

        let invalid_signature = hex::decode("TESTCEnpEHHxenDkY6/4oOLyhqjt5Y646OKN9JJXOhOz8qWxCC6D").unwrap();
        assert!(!signer.verify(message1, &invalid_signature));
    }
}
