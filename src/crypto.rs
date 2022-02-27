#![allow(dead_code)]
#![allow(unused_imports)]

use aead;
use aead::{Aead, AeadCore, AeadInPlace, Key, NewAead, Nonce, Tag};
use chacha20poly1305;
use chacha20poly1305::XChaCha20Poly1305;
use digest;
use digest::Digest;
use generic_array;
use generic_array::typenum::U24;
use generic_array::typenum::U32;
use generic_array::typenum::U64;
use generic_array::GenericArray;
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
use std::mem;
use std::mem::size_of;
use std::ops::Deref;
use std::ops::DerefMut;
use std::ptr;
use std::ptr::drop_in_place;
use std::ptr::NonNull;
use typenum;
use typenum::type_operators::IsEqual;
use typenum::ToInt;
use typenum::True;
use typenum::UInt;
use typenum::Unsigned;

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
pub struct EncBox<T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
{
    _marker: PhantomData<T>,
    /*
     * Can't use an array because of const_generics
     * Can't use GenericArray because of const_convert preventing size_of->UInt conversion
     * Can't use Box<T> because of CipherTextOverhead
     * Therefore has to be a pointer
     */
    ptr: NonNull<T>,
    key: Key<Cipher>,
    nonce: Nonce<Cipher>,
    tag: Tag<Cipher>,
    //Currently holds the size of T
    aad: usize,
}

impl<T, Cipher> EncBox<T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
{
    fn get_data_layout() -> Layout {
        let size = mem::size_of::<T>() + Cipher::CiphertextOverhead::to_usize();
        let align = mem::align_of::<T>();

        debug_assert!(Layout::from_size_align(size, align).is_ok());
        Layout::from_size_align(size, align).unwrap()
    }
    fn alloc_backing_data() -> NonNull<T> {
        let layout = Self::get_data_layout();
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

    //Only failure is decryption related, which intentionally panics
    pub fn decrypt(&mut self) -> EncBoxGuard<'_, T, Cipher> {
        EncBoxGuard { encbox: self }
    }

    pub fn new(data: T) -> EncBox<T, Cipher> {
        let mut ret = EncBox {
            _marker: PhantomData,
            ptr: Self::alloc_backing_data(),
            key: Cipher::generate_key(OsRng),
            nonce: GenericArray::default(),
            tag: GenericArray::default(),
            aad: size_of::<T>(),
        };

        //let keyed = Cipher::new(&ret.key);
        //let dest: &mut [u8];

        //ret.tag = keyed
        //    .encrypt_in_place_detached(&ret.nonce, &usize::to_be_bytes(ret.aad), dest)
        //    .unwrap();

        Self::copy_data_to_ptr(&mut ret.ptr, data);
        ret
    }
}

impl<T, Cipher> Drop for EncBox<T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
{
    fn drop(&mut self) {
        let layout = Self::get_data_layout();
        unsafe {
            drop_in_place(self.ptr.as_ptr());
            dealloc(self.ptr.as_ptr() as *mut u8, layout);
        }
    }
}

impl<T, Cipher> Deref for EncBox<T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T, Cipher> DerefMut for EncBox<T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
{
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
pub struct EncBoxGuard<'a, T, Cipher>
where
    T: Sized + 'a,
    Cipher: NewAead + AeadInPlace,
{
    encbox: &'a mut EncBox<T, Cipher>,
}

impl<'a, T, Cipher> Drop for EncBoxGuard<'a, T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
{
    fn drop(&mut self) {
        self.encbox.ratchet_underlying();
    }
}

impl<'a, T, Cipher> Deref for EncBoxGuard<'a, T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.encbox.ptr.as_ref() }
    }
}

impl<'a, T, Cipher> DerefMut for EncBoxGuard<'a, T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.encbox.ptr.as_mut() }
    }
}
