#![allow(dead_code)]
#![allow(unused_imports)]

use aead::{Aead, Key, NewAead, Nonce};
use digest::Digest;
use generic_array::typenum::U24;
use generic_array::typenum::U32;
use generic_array::typenum::U64;
use generic_array::GenericArray;
use typenum::type_operators::IsEqual;
use typenum::True;

use proc_macro::TokenStream;
use proc_macro2::Literal;
use proc_macro2::Punct;
use proc_macro2::Spacing;
use proc_macro2::Span;
use proc_macro2::TokenTree;
use quote::*;
use syn::ext::*;
use syn::fold::*;
use syn::parse::*;
use syn::spanned::Spanned;
use syn::visit_mut::*;
use syn::*;

use chacha20poly1305::XChaCha20Poly1305;

use r2d2_utils::*;
use r2d2_utils::rand::rngs::OsRng;
use r2d2_utils::rand::RngCore;

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

struct MemEncCtx(MemoryEncryptionCtx<XChaCha20Poly1305>);

impl ToTokens for MemEncCtx {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let key = &self.0.key;
        let nonce = &self.0.nonce;
        let ciphertext = &self.0.ciphertext;

        let key_name = format_ident!("R2D2_Key_{}{}", OsRng.next_u64(), OsRng.next_u64());
        let nonce_name = format_ident!("R2D2_Nonce_{}{}", OsRng.next_u64(), OsRng.next_u64());
        let ciphertext_name = format_ident!("R2D2_Ciphertext_{}{}", OsRng.next_u64(), OsRng.next_u64());


        //TODO: Can we make this more efficient? (Avoid clone)
        let output = quote! {
            let #key_name = [#(#key),*];
            let #nonce_name = [#(#nonce),*];
            let #ciphertext_name = [#(#ciphertext),*];
            let result = r2d2::decrypt_memory::<r2d2::XChaCha20Poly1305>(MemoryEncryptionCtx {
                key: r2d2::Key::<XChaCha20Poly1305>::clone_from_slice(&#key_name),
                nonce: r2d2::Nonce::<XChaCha20Poly1305>::clone_from_slice(&#nonce_name),
                ciphertext: #ciphertext_name.iter().copied().collect(),
            });
            std::string::String::from_utf8(result.clone()).unwrap()
        };

        //eprintln!("What is the output {:#?}", output);

        tokens.append_all(output);
    }
}

struct StrReplace;

impl VisitMut for StrReplace {
    fn visit_macro_mut(&mut self, node: &mut Macro) {
        match node.parse_body::<FormatArgs>() {
            Ok(mut what) => {
                //TODO: Do we need to restrict this to "println!" and "format!" macros?
                if what.positional_args.is_empty() && what.named_args.is_empty() {
                    //Change the string literal to ("{}", "str") to allow block expression replacement
                    let span = what.format_string.span();
                    what.positional_args.push(std::mem::replace(
                        &mut what.format_string,
                        Expr::Lit(ExprLit {
                            attrs: Vec::new(),
                            lit: Lit::Str(LitStr::new("{}", span)),
                        }),
                    ));
                    StrReplace.visit_expr_mut(&mut what.positional_args[0]);
                } else {
                    what.positional_args
                        .iter_mut()
                        .for_each(|mut e| StrReplace.visit_expr_mut(&mut e));
                }
                node.tokens = what.to_token_stream();
            }
            Err(_) => {}
        }
        visit_mut::visit_macro_mut(self, node);
    }
    fn visit_expr_mut(&mut self, node: &mut Expr) {
        if let Expr::Lit(expr) = &node {
            if let Lit::Str(s) = &expr.lit {
                eprintln!("Got a string literal expression!");
                //eprintln!("WOW {:#?}", s);
                let mem_ctx = MemEncCtx(r2d2_utils::encrypt_memory::<XChaCha20Poly1305>(s.value().as_bytes()));
                //let test = quote! {
                //    {
                //        #mem_ctx;
                //        #s
                //    }
                //};
                let test = quote! {
                    {
                        #mem_ctx
                    }
                };
                let test = syn::parse2::<ExprBlock>(test).unwrap();
                //eprintln!("CHANGE {:#?}", test);
                *node = Expr::Block(test);
                return;
            }
        }
        // Delegate to the default impl to visit nested expressions.
        visit_mut::visit_expr_mut(self, node);
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
    //TODO: Remove the TokenStream clone when things are stabilized
    //eprintln!("INPUT: {:#?}", input);
    let input2 = input.clone();
    let _ = parse_macro_input!(args as AttributeArgs);
    let mut input2 = parse_macro_input!(input2 as ItemFn);

    //eprintln!("INPUT: {:#?}", input2);

    StrReplace.visit_item_fn_mut(&mut input2);

    //eprintln!("OUTPUT: {:#?}", input2);

    input2.to_token_stream().into()
}
