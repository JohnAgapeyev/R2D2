#![allow(dead_code)]
#![allow(unused_imports)]

pub use aead;
pub use digest;
pub use generic_array;
pub use rand;
pub use typenum;

use aead::{Aead, Key, NewAead, Nonce};
use digest::Digest;
use generic_array::typenum::U24;
use generic_array::typenum::U32;
use generic_array::typenum::U64;
use rand::rngs::OsRng;
use std::convert::TryInto;
use typenum::type_operators::IsEqual;
use typenum::True;

struct CryptoCtx {
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_counter: u64,
    rx_counter: u64,
}

impl Default for CryptoCtx {
    fn default() -> Self {
        CryptoCtx {
            tx_key: [0u8; 32],
            rx_key: [0u8; 32],
            tx_counter: 0,
            rx_counter: 0,
        }
    }
}

fn encrypt_message<Cipher>(crypto: &mut CryptoCtx, data: &[u8]) -> Vec<u8>
where
    Cipher: NewAead,
    Cipher: Aead,
    Cipher::KeySize: IsEqual<U32, Output = True>,
    //TODO: Should probably redo nonce generation to be generic enough for things like AES-GCM that use 96 bit nonces
    Cipher::NonceSize: IsEqual<U24, Output = True>,
{
    let key = Key::<Cipher>::from_slice(&crypto.tx_key);
    let cipher = Cipher::new(key);
    let nonce_contents = format!("Nonce{:0>19}", crypto.tx_counter);
    println!("Encrypting with nonce:\n{:02X?}", nonce_contents);
    let nonce = Nonce::<Cipher>::from_slice(nonce_contents.as_bytes());
    if crypto.tx_counter != u64::MAX {
        crypto.tx_counter += 1;
    } else {
        panic!("Tx counter overflow");
    }
    //TODO: Probably shouldn't panic on failure
    cipher.encrypt(nonce, data).unwrap()
}

fn decrypt_message<Cipher>(crypto: &mut CryptoCtx, data: &[u8]) -> Vec<u8>
where
    Cipher: NewAead,
    Cipher: Aead,
    Cipher::KeySize: IsEqual<U32, Output = True>,
    //TODO: Should probably redo nonce generation to be generic enough for things like AES-GCM that use 96 bit nonces
    Cipher::NonceSize: IsEqual<U24, Output = True>,
{
    let key = Key::<Cipher>::from_slice(&crypto.rx_key);
    let cipher = Cipher::new(key);
    let nonce_contents = format!("Nonce{:0>19}", crypto.rx_counter);
    println!("Decrypting with nonce:\n{:02X?}", nonce_contents);
    let nonce = Nonce::<Cipher>::from_slice(nonce_contents.as_bytes());
    if crypto.rx_counter != u64::MAX {
        crypto.rx_counter += 1;
    } else {
        panic!("Tx counter overflow");
    }
    //TODO: Probably shouldn't panic on failure
    cipher.decrypt(nonce, data).unwrap()
}

