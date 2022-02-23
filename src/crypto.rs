#![allow(dead_code)]
#![allow(unused_imports)]

use aead;
use aead::{Aead, Key, NewAead, Nonce};
use chacha20poly1305;
use chacha20poly1305::XChaCha20Poly1305;
use digest;
use digest::Digest;
use generic_array;
use generic_array::typenum::U24;
use generic_array::typenum::U32;
use generic_array::typenum::U64;
use generic_array::GenericArray;
use proc_macro2::Literal;
use proc_macro2::Punct;
use proc_macro2::Spacing;
use proc_macro2::Span;
use proc_macro2::TokenTree;
use quote::*;
use rand;
use rand::prelude::*;
use rand::rngs::OsRng;
use rand::RngCore;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::ops::Deref;
use std::ops::DerefMut;
use std::ptr;
use syn::ext::*;
use syn::fold::*;
use syn::parse::*;
use syn::spanned::Spanned;
use syn::visit::*;
use syn::visit_mut::*;
use syn::*;
use typenum;
use typenum::type_operators::IsEqual;
use typenum::True;
//TODO: Is there a better way to handle this?
use crate as r2d2;

//TODO: Consolidate RNG into a "chosen" one to avoid mistakes

struct CryptoCtx {
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_counter: u64,
    rx_counter: u64,
}

pub struct MemoryEncryptionCtx<Cipher>
where
    Cipher: NewAead,
    Cipher: Aead,
    Cipher::KeySize: IsEqual<U32, Output = True>,
    //TODO: Should probably redo nonce generation to be generic enough for things like AES-GCM that use 96 bit nonces
    Cipher::NonceSize: IsEqual<U24, Output = True>,
{
    pub key: Key<Cipher>,
    pub nonce: Nonce<Cipher>,
    pub ciphertext: Vec<u8>,
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

pub fn encrypt_memory<Cipher>(data: &[u8]) -> MemoryEncryptionCtx<Cipher>
where
    Cipher: NewAead,
    Cipher: Aead,
    Cipher::KeySize: IsEqual<U32, Output = True>,
    //TODO: Should probably redo nonce generation to be generic enough for things like AES-GCM that use 96 bit nonces
    Cipher::NonceSize: IsEqual<U24, Output = True>,
{
    let mut key: Key<Cipher> = Default::default();
    OsRng.fill_bytes(&mut key);
    let cipher = Cipher::new(&key);
    let mut nonce: Nonce<Cipher> = Default::default();
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher.encrypt(&nonce, data).unwrap();

    //println!("We are encrypting data: {:#x?}", data);
    //println!("Resulting ciphertext: {:#x?}", ciphertext);

    MemoryEncryptionCtx::<Cipher> {
        key,
        nonce,
        ciphertext,
    }
}

pub fn decrypt_memory<Cipher>(ctx: MemoryEncryptionCtx<Cipher>) -> Vec<u8>
where
    Cipher: NewAead,
    Cipher: Aead,
    Cipher::KeySize: IsEqual<U32, Output = True>,
    //TODO: Should probably redo nonce generation to be generic enough for things like AES-GCM that use 96 bit nonces
    Cipher::NonceSize: IsEqual<U24, Output = True>,
{
    let cipher = Cipher::new(&ctx.key);
    let output = cipher
        .decrypt(&ctx.nonce, ctx.ciphertext.as_slice())
        .unwrap();
    //println!("We decrypted data: {:#x?}", output);
    output
}

#[derive(Debug, Clone, Copy, Hash)]
pub struct EncBox<T>
where
    T: ?Sized,
{
    underlying: PhantomData<T>,
    //TODO: Figure out what approach to use for the underlying memory
    //We need it encrypted and convertable between bytes and type T
    buffer: *mut T,
}

impl<T> EncBox<T> {
    pub fn new() -> EncBox<T> {
        EncBox {
            underlying: PhantomData,
            buffer: ptr::null_mut(),
        }
    }
    pub fn new_with_data(mut data: T) -> EncBox<T> {
        EncBox {
            underlying: PhantomData,
            buffer: ptr::addr_of_mut!(data),
        }
    }
}

impl<T> Deref for EncBox<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        //&self.value
        unimplemented!();
    }
}

impl<T> DerefMut for EncBox<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        //&mut self.value
        unimplemented!();
    }
}
