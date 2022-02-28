#![allow(dead_code)]
#![allow(unused_imports)]

use aead;
use aead::{Aead, AeadInPlace, Key, NewAead, Nonce, Tag};
use blake2::Blake2b512;
use chacha20poly1305;
use chacha20poly1305::XChaCha20Poly1305;
use digest;
use digest::Digest;
use generic_array;
use generic_array::typenum::U24;
use generic_array::typenum::U32;
use generic_array::typenum::U64;
use generic_array::GenericArray;
use hkdf::SimpleHkdf;
use rand;
use rand::rngs::OsRng;
use rand::CryptoRng;
use rand::RngCore;
use std::alloc::alloc;
use std::alloc::dealloc;
use std::alloc::handle_alloc_error;
use std::alloc::Layout;
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
use typenum::True;
use typenum::Unsigned;
use zeroize::Zeroize;

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

//TODO: Add memory protections (locking, RWX permissions, etc)
#[derive(Debug, Clone, Hash)]
pub struct EncBox<T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
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
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
{
    fn ciphertext_size() -> usize {
        mem::size_of::<T>() + Cipher::CiphertextOverhead::to_usize()
    }
    fn get_data_layout() -> Layout {
        let size = Self::ciphertext_size();
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

    fn encrypt(
        key: &Key<Cipher>,
        nonce: &Nonce<Cipher>,
        aad: &[u8],
        contents: &NonNull<T>,
    ) -> Tag<Cipher> {
        let keyed = Cipher::new(key);
        let dest: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(contents.as_ptr() as *mut u8, Self::ciphertext_size())
        };
        keyed.encrypt_in_place_detached(nonce, aad, dest).unwrap()
    }

    //TODO: Add checks to guarantee we are decrypted at this point
    fn ratchet_underlying(&mut self) {
        let src_slice: &[u8] = unsafe {
            std::slice::from_raw_parts(self.ptr.as_ptr() as *const u8, Self::ciphertext_size())
        };
        let newbox = Self::new_from_ptr(src_slice);
        //The old data will have its destructor called, which will zeroize the underlying
        *self = newbox;
    }

    //Only failure is decryption related, which intentionally panics
    pub fn decrypt(&mut self) -> EncBoxGuard<'_, T, Cipher> {
        let keyed = Cipher::new(&self.key);
        let dest: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(self.ptr.as_ptr() as *mut u8, Self::ciphertext_size())
        };

        keyed
            .decrypt_in_place_detached(&self.nonce, &usize::to_be_bytes(self.aad), dest, &self.tag)
            .unwrap();
        EncBoxGuard { encbox: self }
    }

    //Grab a slice since we want to use the input data, and need a slice len to guarantee safe
    //reading
    fn new_from_ptr(data: &[u8]) -> EncBox<T, Cipher> {
        let mut ret = EncBox {
            _marker: PhantomData,
            ptr: Self::alloc_backing_data(),
            key: Cipher::generate_key(OsRng),
            //TODO: Generate nonces properly
            nonce: GenericArray::default(),
            tag: GenericArray::default(),
            aad: size_of::<T>(),
        };

        unsafe {
            std::ptr::copy_nonoverlapping(
                ret.ptr.as_ptr() as *mut u8,
                data.as_ptr() as *mut u8,
                data.len(),
            );
        }

        ret.tag = Self::encrypt(&ret.key, &ret.nonce, &usize::to_be_bytes(ret.aad), &ret.ptr);
        ret
    }

    pub fn new(data: T) -> EncBox<T, Cipher> {
        let src_slice: &[u8] = unsafe {
            std::slice::from_raw_parts(std::ptr::addr_of!(data) as *const u8, size_of::<T>())
        };
        Self::new_from_ptr(src_slice)
    }
}

impl<T, Cipher> Drop for EncBox<T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
{
    fn drop(&mut self) {
        let layout = Self::get_data_layout();
        unsafe {
            drop_in_place(self.ptr.as_ptr());
        }
        self.zeroize();
        unsafe {
            dealloc(self.ptr.as_ptr() as *mut u8, layout);
        }
    }
}

impl<T, Cipher> Deref for EncBox<T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
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
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.ptr.as_mut() }
    }
}

impl<T, Cipher> From<T> for EncBox<T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
{
    fn from(data: T) -> Self {
        EncBox::<T, Cipher>::new(data)
    }
}

impl<T, Cipher> From<&T> for EncBox<T, Cipher>
where
    T: Sized + ToOwned<Owned = T>,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
{
    fn from(data: &T) -> Self {
        EncBox::<T, Cipher>::new(data.to_owned())
    }
}

impl<T, Cipher> Zeroize for EncBox<T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
{
    fn zeroize(&mut self) {
        //PhantomData is zero sized, so ignore it
        self.key.zeroize();
        self.nonce.zeroize();
        self.tag.zeroize();
        self.aad.zeroize();

        let backing: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(self.ptr.as_ptr() as *mut u8, Self::ciphertext_size())
        };
        backing.zeroize();
    }
}

pub struct EncBoxGuard<'a, T, Cipher>
where
    T: Sized + 'a,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
{
    encbox: &'a mut EncBox<T, Cipher>,
}

impl<'a, T, Cipher> Drop for EncBoxGuard<'a, T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
{
    fn drop(&mut self) {
        self.encbox.ratchet_underlying();
    }
}

impl<'a, T, Cipher> Deref for EncBoxGuard<'a, T, Cipher>
where
    T: Sized,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
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
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.encbox.ptr.as_mut() }
    }
}
