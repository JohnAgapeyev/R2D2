#![allow(dead_code)]
#![allow(unused_imports)]

use proc_macro::TokenStream;
use proc_macro2::TokenTree;
use proc_macro2::Span;
use proc_macro2::Literal;
use proc_macro2::Punct;
use proc_macro2::Spacing;
use quote::quote;
use quote::ToTokens;
use quote::TokenStreamExt;
use syn::*;
use syn::fold::*;
use syn::parse::*;
use syn::visit_mut::*;
use syn::ext::*;

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

// The arguments expected by libcore's format_args macro, and as a
// result most other formatting and printing macros like println.
//
//     println!("{} is {number:.prec$}", "x", prec=5, number=0.01)
#[derive(Debug)]
struct FormatArgs {
    format_string: Expr,
    positional_args: Vec<Expr>,
    named_args: Vec<(Ident, Expr)>,
}

impl Parse for FormatArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let format_string: Expr;
        let mut positional_args = Vec::new();
        let mut named_args = Vec::new();

        format_string = input.parse()?;
        while !input.is_empty() {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }
            if input.peek(Ident::peek_any) && input.peek2(Token![=]) {
                while !input.is_empty() {
                    let name: Ident = input.call(Ident::parse_any)?;
                    input.parse::<Token![=]>()?;
                    let value: Expr = input.parse()?;
                    named_args.push((name, value));
                    if input.is_empty() {
                        break;
                    }
                    input.parse::<Token![,]>()?;
                }
                break;
            }
            positional_args.push(input.parse()?);
        }

        Ok(FormatArgs {
            format_string,
            positional_args,
            named_args,
        })
    }
}

impl ToTokens for FormatArgs {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let format = self.format_string.clone();
        let pos = self.positional_args.clone();

        tokens.append_all(quote! {
            #format, #(#pos),*
        });

        if !self.named_args.is_empty() {
            tokens.append(Punct::new(',', Spacing::Alone));
        }

        for (idx, (ident, expr)) in self.named_args.iter().enumerate() {
            tokens.append_all(quote! {#ident=#expr});

            if idx != self.named_args.len() - 1 {
                tokens.append(Punct::new(',', Spacing::Alone));
            }
        }
    }
}

struct StrReplace;

impl Fold for StrReplace {
    fn fold_lit_str(&mut self, s: LitStr) -> LitStr {
        LitStr::new("Fucking hell", s.span())
    }
}

impl VisitMut for StrReplace {
    fn visit_lit_str_mut(&mut self, node: &mut LitStr) {
        *node = LitStr::new("Fucking hell", node.span());
        visit_mut::visit_lit_str_mut(self, node);
    }
    fn visit_macro_mut(&mut self, node: &mut Macro) {
        match node.parse_body::<FormatArgs>() {
            Ok(mut what) => {
                if what.positional_args.is_empty() && what.named_args.is_empty() {
                    StrReplace.visit_expr_mut(&mut what.format_string);
                } else {
                    what.positional_args.iter_mut().for_each(|mut e| StrReplace.visit_expr_mut(&mut e));
                }
                node.tokens = what.to_token_stream();
            }
            Err(_) => {}
        }
        visit_mut::visit_macro_mut(self, node);
    }
}

/*
 * Plan of attack for full encryption of strings
 * Parse as ItemFn
 * Fold on Expr objects
 * Filter/Match only on ExprLit
 * Filter out ExprLit that aren't strings
 * Replace ExprLit with ExprBlock
 * Generate ExprBlock using quote!
 * Done inside the generic fold_expr call, so we can change the enum type easily
 *
 * If we manage to get RNG output in this proc_macro execution, might not even need to worry about
 * const functions being an annoying edge case
 * Obviously wouldn't help against const function initialization of static strings
 * But for that, you can probably get away with a standard EncryptedBox<String> type move
 * Would need a test to verify that though, but also easy enough to forbid in code review
 */

#[proc_macro_attribute]
pub fn obfuscate(args: TokenStream, input: TokenStream) -> TokenStream {
    //eprintln!("INPUT: {:#?}", input);
    let input2 = input.clone();
    let _ = parse_macro_input!(args as AttributeArgs);
    let mut input2 = parse_macro_input!(input2 as ItemFn);

    eprintln!("INPUT: {:#?}", input2);

    //let replaced = StrReplace.fold_item_fn(input2);
    StrReplace.visit_item_fn_mut(&mut input2);

    input2.to_token_stream().into()
    //replaced.to_token_stream().into()
}
