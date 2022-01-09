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
            //tokens.append_all(quote! {#ident});
            //tokens.append(Literal::character('='));
            //tokens.append_all(quote! {#expr});

            tokens.append_all(quote! {#ident=#expr});

            if idx != self.named_args.len() - 1 {
                tokens.append(Punct::new(',', Spacing::Alone));
            }

            //format_names.push(ExprAssign {
            //    attrs: Vec::new(),
            //    left: Box::new(Expr::Lit(ExprLit{
            //        attrs: Vec::new(),
            //        lit: Lit::Str(LitStr::new(&ident.to_string(), Span::call_site())),
            //    })),
            //    eq_token: Default::default(),
            //    right: Box::new(expr)
            //});
        }
    }
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
        //let tokens = node.tokens.clone();
        //let tokens2 = node.tokens.clone();
        //let tokens3 = node.tokens.clone();

        //for obj in tokens2.into_iter() {
        //eprintln!("Size hint {:#?}", tokens3.into_iter().last());
        //let mut iter = tokens2.into_iter();
        //for obj in tokens2.into_iter().next() {
        //for (idx, obj) in iter.enumerate() {
            //eprintln!("SHIT {}: {:#?}", idx, obj);
        //}

        //let tokens = node.parse_body();
        //let args: FormatArgs = m.parse_body()?;
        //match syn::parse2::<LitStr>(tokens) {
        //match syn::parse2::<ExprArray>(tokens) {
        match node.parse_body::<FormatArgs>() {
        //match node.parse_body::<File>() {
            Ok(mut what) => {
                //eprintln!("FANCY: {:#?}", what);
                //StrReplace.visit_lit_str_mut(&mut what);
                //let test = what.clone();
                //for mut e in what.positional_args {
                    //StrReplace.visit_expr_mut(&mut e);
                //}
                if what.positional_args.is_empty() && what.named_args.is_empty() {
                    StrReplace.visit_expr_mut(&mut what.format_string);
                } else {
                    what.positional_args.iter_mut().for_each(|mut e| StrReplace.visit_expr_mut(&mut e));
                }
                eprintln!("FANCY: {:#?}", what);

                //let format = what.format_string;
                //let pos = what.positional_args;

                //let mut format_names: Vec<ExprAssign> = Vec::with_capacity(what.named_args.len());
                //for (ident, expr) in what.named_args {
                //    format_names.push(ExprAssign {
                //        attrs: Vec::new(),
                //        left: Box::new(Expr::Lit(ExprLit{
                //            attrs: Vec::new(),
                //            lit: Lit::Str(LitStr::new(&ident.to_string(), Span::call_site())),
                //        })),
                //        eq_token: Default::default(),
                //        right: Box::new(expr)
                //    });
                //}

                //if format_names.len() > 0 {
                //    eprintln!("FUCK: {:#?}", format_names[0]);
                //}

                //let simple = quote! {
                //    #format, #(#pos),*
                //};
                //let pairs = quote! {
                //    #(#format_names),*
                //};
                //let output = quote! {
                //    #simple #pairs
                //};
                //eprintln!("AMAZING: {:#?}", output);
                //eprintln!("AMAZING: {:#?}", what.to_token_stream());
                node.tokens = what.to_token_stream();
                eprintln!("OUTPUT: {:#?}", node.tokens);
            }
            Err(_) => {}
        }

        //let count = tokens.into_iter().count();
        //for (idx, mut obj) in tokens2.into_iter().enumerate() {
        //    if count > 1 {
        //        if node.path.is_ident("println") || node.path.is_ident("format") {
        //            if idx == 0 {
        //                continue;
        //            }
        //        }
        //    }
        //    match obj {
        //        Literal(n) => {
        //            let stream: proc_macro2::TokenStream = proc_macro2::TokenStream::from(TokenTree::from(n));
        //            match syn::parse2::<LitStr>(stream) {
        //                Ok(what) => {
        //                    eprintln!("WOW: {:#?}", what);
        //                    //StrReplace.visit_lit_str_mut(&mut what);
        //                    //node.tokens = what.to_token_stream();
        //                    obj = TokenTree::from(proc_macro2::Literal::string("TEST"));
        //                }
        //                Err(_) => {}
        //            }
        //        }
        //        _ => {}
        //    }
        //}




        //let replaced = StrReplace.fold_item_fn(input2);
        //eprintln!("FANCY: {:#?}", node.tokens);
        visit_mut::visit_macro_mut(self, node);
    }
}

#[proc_macro_attribute]
pub fn obfuscate(args: TokenStream, input: TokenStream) -> TokenStream {
    //eprintln!("INPUT: {:#?}", input);
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
