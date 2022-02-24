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
use std::alloc::alloc;
use std::alloc::dealloc;
use std::alloc::handle_alloc_error;
use std::alloc::Layout;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::ops::Deref;
use std::ops::DerefMut;
use std::ptr;
use std::ptr::NonNull;
use std::ptr::drop_in_place;
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

#[derive(Debug, Clone, Hash)]
pub struct EncBox<T>
where
    T: Sized,
{
    _marker: PhantomData<T>,
    ptr: NonNull<T>,
}

impl<T> EncBox<T> {
    fn get_data_layout() -> Layout {
        Layout::new::<T>()
    }
    fn alloc_backing_data() -> NonNull<T> {
        let layout = EncBox::<T>::get_data_layout();
        let data = NonNull::new(unsafe { alloc(layout) } as *mut T);

        if let Some(p) = data {
            return p;
        } else {
            handle_alloc_error(layout);
        }
    }

    fn copy_data_to_ptr(dest: &mut NonNull<T>, src: T) {
        unsafe { ptr::write(dest.as_ptr(), src) };
    }

    fn ratchet_underlying(&mut self) {
        unimplemented!();
    }

    pub fn new() -> EncBox<T> {
        EncBox {
            _marker: PhantomData,
            ptr: NonNull::dangling(),
        }
    }
    pub fn new_with_data(data: T) -> EncBox<T> {
        let mut ret = EncBox {
            _marker: PhantomData,
            ptr: EncBox::alloc_backing_data(),
        };
        EncBox::copy_data_to_ptr(&mut ret.ptr, data);
        ret
    }
}

impl<T> Drop for EncBox<T> {
    fn drop(&mut self) {
        let layout = EncBox::<T>::get_data_layout();
        unsafe {
            drop_in_place(self.ptr.as_ptr());
            dealloc(self.ptr.as_ptr() as *mut u8, layout);
        }
    }
}

impl<T> Deref for EncBox<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> DerefMut for EncBox<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.ptr.as_mut() }
    }
}

//TODO: I don't think this will work how I want
//The deref trait returns a &Target, not a Target
//So I'd effectively have to have a lifetime notification for an arbitrary reference
//Which doesn't make sense when it's raw like that
//I can store the reference to an underlying object, but would have no notification when things go
//out of scope in order to ratchet keys
//So I probably will have to concede my vision and just aim for a normal smart pointer approach
//I can make it easy to use, with all the boilerplate
//But I don't think I can get it to a truly transparent automated type replacement mechanism
//Next best step will be emulating Mutex<T> or Rc<T> or what have you
//Maybe call it EArc<T> or EncArc<T>, who knows
struct EncBoxGuard<'a, T>
where
    T: Sized + 'a,
{
    encbox: &'a mut EncBox<T>,
}

impl<'a, T> Drop for EncBoxGuard<'a, T> {
    fn drop(&mut self) {
        self.encbox.ratchet_underlying();
    }
}

impl<'a, T> Deref for EncBoxGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.encbox.ptr.as_ref() }
    }
}

impl<'a, T> DerefMut for EncBoxGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.encbox.ptr.as_mut() }
    }
}
