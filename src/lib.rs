#![allow(dead_code)]
#![allow(unused_imports)]

use proc_macro::TokenStream;
use quote::quote;
use quote::ToTokens;
use syn::*;
use syn::fold::*;
use syn::visit_mut::*;

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

struct StrReplace;

impl Fold for StrReplace {
    fn fold_lit_str(&mut self, s: LitStr) -> LitStr {
        eprintln!("WHAT THE FUCK");
        LitStr::new("Fucking hell", s.span())
    }
}

impl VisitMut for StrReplace {
    fn visit_lit_str_mut(&mut self, node: &mut LitStr) {
        eprintln!("WHAT THE FUCK FUCK {}", node.token());
        *node = LitStr::new("Fucking hell", node.span());
        visit_mut::visit_lit_str_mut(self, node);
    }
    fn visit_lit_mut(&mut self, node: &mut Lit) {
        //eprintln!("WHAT THE FUCK");
        //eprintln!("FANCY: {:#?}", node);
        //*node = LitStr::new("Fucking hell", node.span());
        visit_mut::visit_lit_mut(self, node);
    }
    fn visit_macro_mut(&mut self, node: &mut Macro) {
        let tokens = node.tokens.clone().into();
        //let mut what = parse_macro_input!(tokens as ItemFn);
        match syn::parse2::<LitStr>(tokens) {
            Ok(mut what) => {
                eprintln!("FANCY: {:#?}", what);
                StrReplace.visit_lit_str_mut(&mut what);
                node.tokens = what.to_token_stream();
            }
            Err(_) => {}
        }
        //let replaced = StrReplace.fold_item_fn(input2);
        //eprintln!("FANCY: {:#?}", node.tokens);
        visit_mut::visit_macro_mut(self, node);
    }
}

#[proc_macro_attribute]
pub fn obfuscate(args: TokenStream, input: TokenStream) -> TokenStream {
    eprintln!("INPUT: {:#?}", input);
    let input2 = input.clone();
    let _ = parse_macro_input!(args as AttributeArgs);
    let mut input2 = parse_macro_input!(input2 as ItemFn);

    //let replaced = StrReplace.fold_item_fn(input2);
    StrReplace.visit_item_fn_mut(&mut input2);

    //let output = quote! {
        //#input2
    //};

    //let test = TokenStream::from(output);

    //println!("Fuck?");
    eprintln!("The Fuck?");
    //eprintln!("INPUT: {:#?}", input2);
    //eprintln!("OUTPUT: {:#?}", test);
    //eprintln!("OUTPUT: {:#?}", output);
    //eprintln!("OUTPUT: {:#?}", input2);
    //eprintln!("OUTPUT: {:#?}", replaced);

    //TokenStream::from(output)
    //test
    //output.into()
    input2.to_token_stream().into()
    //replaced.to_token_stream().into()
}
