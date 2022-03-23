#![allow(dead_code)]
#![allow(unused_imports)]

pub use aead;
pub use aead::{Aead, AeadInPlace, Key, NewAead, Nonce, Tag};
pub use blake2::Blake2b512;
pub use chacha20poly1305;
pub use chacha20poly1305::XChaCha20Poly1305;
pub use digest;
pub use digest::Digest;
pub use generic_array;
pub use generic_array::typenum::U0;
pub use generic_array::typenum::U24;
pub use generic_array::typenum::U32;
pub use generic_array::typenum::U64;
pub use generic_array::GenericArray;
pub use hkdf::SimpleHkdf;
pub use rand;
pub use rand::rngs::OsRng;
pub use rand::CryptoRng;
pub use rand::RngCore;
pub use std::alloc::alloc;
pub use std::alloc::dealloc;
pub use std::alloc::handle_alloc_error;
pub use std::alloc::Layout;
pub use std::fmt;
pub use std::fmt::*;
pub use std::marker::PhantomData;
pub use std::mem;
pub use std::mem::size_of;
pub use std::mem::ManuallyDrop;
pub use std::ops::Deref;
pub use std::ops::DerefMut;
pub use std::ptr;
pub use std::ptr::drop_in_place;
pub use std::ptr::NonNull;
pub use typenum;
pub use typenum::type_operators::IsEqual;
pub use typenum::True;
pub use typenum::Unsigned;
pub use zeroize::Zeroize;

//TODO: Is there a better way to handle this?
use crate as r2d2;

#[derive(Default)]
struct CryptoCtx {
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_counter: u64,
    rx_counter: u64,
}

#[derive(Debug, Default, Hash, PartialEq)]
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

#[derive(Clone, Copy, Debug, Hash, PartialEq)]
enum EncBoxState {
    Decrypted,
    Encrypted,
}

//TODO: Add memory protections (locking, RWX permissions, etc)
#[derive(Clone, Hash, PartialEq)]
pub struct EncBox<T, Cipher>
where
    T: Sized + ToOwned<Owned = T>,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
    //We assume no excess bytes in ciphertext, so Box<T> can hold the encrypted data, don't need to
    //allocate extra data or handle that unsafe mess
    Cipher::CiphertextOverhead: IsEqual<U0, Output = True>,
{
    _marker: PhantomData<T>,
    /*
     * Can't use an array because of const_generics
     * Can't use GenericArray because of const_convert preventing size_of->UInt conversion
     * Box<T> only works due to constraint that CiphertextOverhead == 0
     * ManuallyDrop<Box<T>> is to inhibit the box drop so we can manually drop it with memory zeroing
     */
    data: ManuallyDrop<Box<T>>,
    key: Key<Cipher>,
    nonce: Nonce<Cipher>,
    tag: Tag<Cipher>,
    //Currently holds the size of T
    aad: usize,
    state: EncBoxState,
}

impl<T, Cipher> EncBox<T, Cipher>
where
    T: Sized + ToOwned<Owned = T>,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
    Cipher::CiphertextOverhead: IsEqual<U0, Output = True>,
{
    fn ratchet_underlying(&mut self) {
        debug_assert!(self.state == EncBoxState::Decrypted);
        *self = Self::from(&**self.data);
    }

    //Only failure is decryption related, which intentionally panics
    fn decrypt_underlying(&mut self) {
        let keyed = Cipher::new(&self.key);
        let dest: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                std::ptr::addr_of_mut!(**self.data) as *mut u8,
                size_of::<T>(),
            )
        };

        keyed
            .decrypt_in_place_detached(&self.nonce, &usize::to_be_bytes(self.aad), dest, &self.tag)
            .unwrap();
        self.state = EncBoxState::Decrypted;
    }

    pub fn decrypt(&mut self) -> EncBoxGuard<'_, T, Cipher> {
        debug_assert!(self.state == EncBoxState::Encrypted);
        self.decrypt_underlying();
        EncBoxGuard { encbox: self }
    }

    fn generate_nonce() -> Nonce<Cipher> {
        /*
         * We always ratchet when re-encrypting, which generates a new key+nonce combo, so randomly
         * generating them is fine, neither key nor nonce will be reused
         */
        let mut nonce: Nonce<Cipher> = GenericArray::default();
        OsRng.fill_bytes(nonce.as_mut_slice());
        nonce
    }

    pub fn new(data: T) -> EncBox<T, Cipher> {
        let mut ret = EncBox {
            _marker: PhantomData,
            data: ManuallyDrop::new(Box::new(data)),
            key: Cipher::generate_key(OsRng),
            nonce: Self::generate_nonce(),
            tag: GenericArray::default(),
            aad: size_of::<T>(),
            state: EncBoxState::Decrypted,
        };
        let dest: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                std::ptr::addr_of_mut!(**ret.data) as *mut u8,
                size_of::<T>(),
            )
        };
        let keyed = Cipher::new(&ret.key);
        ret.tag = keyed
            .encrypt_in_place_detached(&ret.nonce, &usize::to_be_bytes(ret.aad), dest)
            .unwrap();
        ret.state = EncBoxState::Encrypted;
        ret
    }
}

impl<T, Cipher> Drop for EncBox<T, Cipher>
where
    T: Sized + ToOwned<Owned = T>,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
    Cipher::CiphertextOverhead: IsEqual<U0, Output = True>,
{
    fn drop(&mut self) {
        if self.state == EncBoxState::Encrypted {
            self.decrypt_underlying();
        }
        //Zero out the underlying data
        self.key.zeroize();
        self.nonce.zeroize();
        self.tag.zeroize();
        self.aad.zeroize();

        /*
         * SAFETY: This is necessary to zero out the contents of the data pointer effectively
         * Box::zeroize doesn't work when T isn't Default+Copy
         * If we zeroize the underlying bytes manually, it leaks (or worse!) due to our drop being
         * called prior to actual member drop
         */
        unsafe {
            //Needed to work around mutable reference preventing moving data in directly
            let raw_data = ManuallyDrop::take(&mut self.data);
            //Grab the raw pointer out of the box
            let data_ptr = Box::into_raw(raw_data);
            //Treat the raw pointer as a u8 slice we can zero
            let byte_data_slice: &mut [u8] =
                std::slice::from_raw_parts_mut(data_ptr as *mut u8, size_of::<T>());
            //Call the destructor for the box
            ptr::drop_in_place(data_ptr);
            //Zero out the data
            byte_data_slice.zeroize();
            //Free the underlying
            dealloc(data_ptr as *mut u8, Layout::new::<T>());
        }
    }
}

impl<T, Cipher> Deref for EncBox<T, Cipher>
where
    T: Sized + ToOwned<Owned = T>,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
    Cipher::CiphertextOverhead: IsEqual<U0, Output = True>,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        debug_assert!(self.state == EncBoxState::Decrypted);
        self.data.as_ref()
    }
}

impl<T, Cipher> DerefMut for EncBox<T, Cipher>
where
    T: Sized + ToOwned<Owned = T>,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
    Cipher::CiphertextOverhead: IsEqual<U0, Output = True>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        debug_assert!(self.state == EncBoxState::Decrypted);
        self.data.as_mut()
    }
}

impl<T, Cipher> From<T> for EncBox<T, Cipher>
where
    T: Sized + ToOwned<Owned = T>,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
    Cipher::CiphertextOverhead: IsEqual<U0, Output = True>,
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
    Cipher::CiphertextOverhead: IsEqual<U0, Output = True>,
{
    fn from(data: &T) -> Self {
        EncBox::<T, Cipher>::new(data.to_owned())
    }
}

impl<T, Cipher> Debug for EncBox<T, Cipher>
where
    T: Sized + ToOwned<Owned = T>,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
    Cipher::CiphertextOverhead: IsEqual<U0, Output = True>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        //let backing: &[u8] = unsafe {
        //    std::slice::from_raw_parts(self.ptr.as_ptr() as *mut u8, Self::ciphertext_size())
        //};
        //let backing_vec = Vec::from(backing);
        f.debug_struct("EncBox")
            .field("key", &self.key)
            .field("nonce", &self.nonce)
            .field("tag", &self.tag)
            .field("aad", &self.aad)
            //.field("data", &self.data)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Hash, PartialEq)]
pub struct EncBoxGuard<'a, T, Cipher>
where
    T: Sized + ToOwned<Owned = T> + 'a,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
    Cipher::CiphertextOverhead: IsEqual<U0, Output = True>,
{
    encbox: &'a mut EncBox<T, Cipher>,
}

impl<'a, T, Cipher> Drop for EncBoxGuard<'a, T, Cipher>
where
    T: Sized + ToOwned<Owned = T>,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
    Cipher::CiphertextOverhead: IsEqual<U0, Output = True>,
{
    fn drop(&mut self) {
        debug_assert!(self.encbox.state == EncBoxState::Decrypted);
        self.encbox.ratchet_underlying();
    }
}

impl<'a, T, Cipher> Deref for EncBoxGuard<'a, T, Cipher>
where
    T: Sized + ToOwned<Owned = T>,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
    Cipher::CiphertextOverhead: IsEqual<U0, Output = True>,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        debug_assert!(self.encbox.state == EncBoxState::Decrypted);
        self.encbox.data.as_ref()
    }
}

impl<'a, T, Cipher> DerefMut for EncBoxGuard<'a, T, Cipher>
where
    T: Sized + ToOwned<Owned = T>,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
    Cipher::CiphertextOverhead: IsEqual<U0, Output = True>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        debug_assert!(self.encbox.state == EncBoxState::Decrypted);
        self.encbox.data.as_mut()
    }
}

impl<'a, T, Cipher> Debug for EncBoxGuard<'a, T, Cipher>
where
    T: Sized + ToOwned<Owned = T>,
    Cipher: NewAead + AeadInPlace,
    //Enforce 256 bit keys
    Cipher::KeySize: IsEqual<U32, Output = True>,
    Cipher::CiphertextOverhead: IsEqual<U0, Output = True>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("EncBoxGuard")
            .field("encbox", &self.encbox)
            .finish()
    }
}

#[cfg(test)]
mod enc_box_tests {
    use crate::EncBox;
    use crate::XChaCha20Poly1305;
    #[test]
    fn sanity_check() {
        let basic: String = "FizzBuzz".to_string();
        let mut enc: EncBox<String, XChaCha20Poly1305> = EncBox::from(&basic);
        let contents = enc.decrypt();
        let mut modified: EncBox<String, XChaCha20Poly1305> =
            EncBox::from(contents.replace("zz", "yy"));
        assert_eq!(basic, *contents);
        assert_eq!(*modified.decrypt(), "FiyyBuyy");
    }
}
