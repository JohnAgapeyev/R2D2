#![allow(dead_code)]
#![allow(unused_imports)]

pub use camino::Utf8Path;
pub use camino::Utf8PathBuf;
pub use cargo_metadata::MetadataCommand;
pub use chacha20poly1305;
pub use chacha20poly1305::XChaCha20Poly1305;
pub use clap::{app_from_crate, arg, App, AppSettings};
pub use digest;
pub use digest::Digest;
pub use proc_macro2::Punct;
pub use proc_macro2::Spacing;
pub use quote::*;
pub use rand;
pub use rand::prelude::*;
pub use rand::rngs::OsRng;
pub use std::env;
pub use std::fs;
pub use std::fs::DirBuilder;
pub use std::fs::OpenOptions;
pub use std::io;
pub use std::io::ErrorKind;
pub use std::path::PathBuf;
pub use std::process::Command;
pub use std::process::Stdio;
pub use syn::ext::*;
pub use syn::parse::*;
pub use syn::spanned::Spanned;
pub use syn::visit::*;
pub use syn::visit_mut::*;
pub use syn::*;
pub use walkdir::WalkDir;

//Needed for the quote memory encryption routines to resolve
pub mod crypto;
pub use crate::crypto::*;
//TODO: Is there a better way to handle this?
use crate as r2d2;

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
    fn parse(input: ParseStream) -> syn::parse::Result<Self> {
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

        let output = quote! {
            let result = r2d2::decrypt_memory::<r2d2::chacha20poly1305::XChaCha20Poly1305>(r2d2::MemoryEncryptionCtx {
                key: (r2d2::generic_array::arr![u8; #(#key),*]) as r2d2::crypto::aead::Key::<r2d2::chacha20poly1305::XChaCha20Poly1305>,
                nonce: (r2d2::generic_array::arr![u8; #(#nonce),*]) as r2d2::crypto::aead::Nonce::<r2d2::chacha20poly1305::XChaCha20Poly1305>,
                ciphertext: ::std::vec![#(#ciphertext),*],
            });
            ::std::string::String::from_utf8(result).unwrap().as_str()
        };
        tokens.append_all(output);
    }
}

struct StrReplace;

impl VisitMut for StrReplace {
    fn visit_macro_mut(&mut self, node: &mut Macro) {
        let macro_path = node
            .path
            .get_ident()
            .map(|ident| ident.to_string())
            .unwrap_or_default();
        let mut can_encrypt = match macro_path.as_str() {
            "println" => true,
            "eprintln" => true,
            "format" => true,
            "concat" => true,
            _ => false,
        };

        //Don't even process macros we don't understand
        if !can_encrypt {
            visit_mut::visit_macro_mut(self, node);
            return;
        }

        if let Ok(mut parsed) = node.parse_body::<FormatArgs>() {
            if let Expr::Lit(expr) = &parsed.format_string {
                if let Lit::Str(s) = &expr.lit {
                    //TODO: This is overzealous, it fails on "println!("{}", "Hello World")"
                    //Need to limit this check to the format string
                    if s.value().contains("{") {
                        //Don't mess with format strings that aren't trivial
                        can_encrypt = false;
                    }
                } else {
                    panic!("Format string is not a string literal!");
                }
            } else {
                panic!("Format string is not a literal expression!");
            }

            if parsed.positional_args.is_empty() && parsed.named_args.is_empty() && can_encrypt {
                //Change the string literal to ("{}", "str") to allow block expression replacement
                let span = parsed.format_string.span();
                parsed.positional_args.push(std::mem::replace(
                    &mut parsed.format_string,
                    Expr::Lit(ExprLit {
                        attrs: Vec::new(),
                        lit: Lit::Str(LitStr::new("{}", span)),
                    }),
                ));
                visit_mut::visit_expr_mut(self, &mut parsed.positional_args[0]);
            } else {
                parsed
                    .positional_args
                    .iter_mut()
                    .for_each(|mut e| visit_mut::visit_expr_mut(self, &mut e));
            }
            node.tokens = parsed.to_token_stream();
        }
        visit_mut::visit_macro_mut(self, node);
    }
    fn visit_expr_mut(&mut self, node: &mut Expr) {
        if let Expr::Lit(expr) = &node {
            //TODO: Support ByteStr as well
            if let Lit::Str(s) = &expr.lit {
                let mem_ctx = MemEncCtx(encrypt_memory::<XChaCha20Poly1305>(s.value().as_bytes()));
                let output = quote! {
                    {
                        #mem_ctx
                    }
                };
                let output = syn::parse2::<ExprBlock>(output).unwrap();
                *node = Expr::Block(output);
                return;
            }
        }
        // Delegate to the default impl to visit nested expressions.
        visit_mut::visit_expr_mut(self, node);
    }

    fn visit_arm_mut(&mut self, node: &mut Arm) {
        //Don't visit patterns, those string literals can't be replaced
        visit_mut::visit_expr_mut(self, &mut node.body);
    }
}

struct ExprShuffle {
    list: Vec<Expr>,
}

//TODO: Need scoping, separate shuffle regions, as well as function boundaries
//We don't want to have shuffle being global across a file
impl ExprShuffle {
    fn is_shuffle_attr(attr: &str) -> bool {
        match attr {
            "shufflecase" => true,
            _ => false,
        }
    }
    fn get_attr_name(attr: &Attribute) -> String {
        if let Some(ident) = attr.path.get_ident() {
            ident.to_string()
        } else {
            "".to_string()
        }
    }
    fn contains_shuffle_attr(attrs: &Vec<Attribute>) -> bool {
        for attr in attrs {
            if ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr)) {
                return true;
            }
        }
        return false;
    }

    //TODO: I hate this much code duplication, but I don't have a better idea yet
    fn fetch_shuffled_statements(&mut self, node: &Expr) {
        match node {
            Expr::Array(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Assign(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::AssignOp(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Async(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Await(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Binary(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Block(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Box(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Break(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Call(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Cast(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Closure(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Continue(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Field(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::ForLoop(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Group(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::If(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Index(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Let(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Lit(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Loop(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Macro(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Match(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::MethodCall(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Paren(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Path(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Range(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Reference(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Repeat(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Return(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Struct(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Try(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::TryBlock(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Tuple(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Type(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Unary(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Unsafe(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::While(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Yield(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            _ => {}
        };
    }
    fn replace_shuffle_case(&mut self, attrs: &Vec<Attribute>, node: &Expr) -> Expr {
        if ExprShuffle::contains_shuffle_attr(attrs) && !self.list.is_empty() {
            //TODO: This statement doesn't remove the attribute when I add a shufflecase attribute
            //to it
            //Might need to use Stmt to enforce Semicolon termination at the top level
            //Best guess is that multiple Expressions are getting tripped up
            let selection = self.list.first().unwrap().clone();
            self.list.remove(0);
            return selection;
        }
        node.clone()
    }
}

impl Visit<'_> for ExprShuffle {
    fn visit_expr(&mut self, node: &Expr) {
        self.fetch_shuffled_statements(node);
        // Delegate to the default impl to visit nested expressions.
        visit::visit_expr(self, node);
    }
}
impl VisitMut for ExprShuffle {
    fn visit_expr_mut(&mut self, node: &mut Expr) {
        let new_node = match &*node {
            Expr::Array(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Assign(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::AssignOp(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Async(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Await(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Binary(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Block(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Box(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Break(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Call(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Cast(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Closure(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Continue(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Field(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::ForLoop(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Group(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::If(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Index(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Let(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Lit(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Loop(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Macro(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Match(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::MethodCall(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Paren(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Path(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Range(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Reference(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Repeat(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Return(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Struct(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Try(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::TryBlock(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Tuple(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Type(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Unary(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Unsafe(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::While(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Yield(expr) => self.replace_shuffle_case(&expr.attrs, node),
            _ => node.to_owned(),
        };
        *node = new_node;
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

/*
 * Plan for runtime string encryption
 * Need to make a wrapper type obviously
 * Almost certainly needs to implement Deref and DerefMut
 * Probably also need to wrap my head around Pin<T>
 * One thing I'm concerned about is the lifetime of references to the string
 * AKA, re-encryption when out of scope
 * Might need to hand out a separate "EncStringRef" type, which implements Drop
 *
 * Then have a combo of "string arbiter which decrypts on the fly", and reference thin object
 * which basically exists to encrypt at rest when the reference count is decremented
 * Mutations over the use of the reference should be fine since they'd all be proxied through Deref
 * So things like key rotation wouldn't be noticeable
 */

/*
 * Plan for shatter handling
 * Wait until Rust 1.59, when inline asm should be stabilized
 * Rely on subtle crate for assert checks in false branches
 * asm boundary as an optimization barrier
 * Probably find a nice way of generating arbitrary asm opcodes for junk creation
 * Can just splice them in every other statement in the function
 * May even want to consider adding in threading for kicks
 * Literally just spawn a thread, run that single line of code, then join the thread
 * May not be viable, but it'd be hilarious spawning tons of threads constantly, I bet it'd be
 * awful to RE
 */

/*
 * Plan for reordering
 * Probably can just be lazy and do a 2 pass thing
 * Grab the annotated statements, throw them in a list
 * Shuffle the list
 * Re-pass through the statement block
 * If a statement is annotated, replace it with the head of the shuffled list and pop the head off
 */

/*
 * Plan for call site obfuscation
 * libloading has a "self" function call in the unix/windows specific subsections
 * Can use that to try and get some DLL callbacks for function calls
 * There's also an export_name attribute you can use to rename things for exporting
 * And also another one for section selection
 * So I can totally mess around with creating a ton of garbage ELF sections, or renaming the
 * exported function when called via DLL
 *
 * There's also the possibility of raw function pointer obfuscation
 * Rather than dealing with dlsym for it, just using plain old indirection
 * Found a stack overflow answer that mentioned how to call an arbitrary address (in the context of
 * OS code)
 * Basically, cast the thing as a *const (), which is a void pointer IIRC
 * Then use the almight mem::transmute to transform that into a callable function
 * Definitely needs to be checked and confirmed
 * I'm especially skeptical of ABI boundaries and Rust types working here
 *
 * It'd be a guaranteed problem with the DLL thing, so function pointer calculation would be nicer
 * to have
 * But how would arguments work here?
 * I'm also worried about generic functions too
 * Lot of ways for it to go wrong and shit itself
 * But being able to decrypt a memory address at runtime to call a function would be hilariously
 * sick
 */

/*
 * There is an unstable API in rust for grabbing VTables and creating fat pointers with them
 * It's nowhere close to being standardized, but it's something to watch out for
 * Encrypting VTables would be amazing
 * It's called ptr_metadata, something to keep an eye out for
 */

/*
 * Also should probably get a nightly build up and running just so I can use cargo expand to verify
 * what I'm actually doing at this point
 */

/*
 * Shuffle is on hold pending a better solution
 * Currently, you can't actually add custom attributes to arbitrary statements
 * See the following example:
 *
 *   #[shuffle]
 *   fn shuffled() {
 *       #[shufflecase]
 *       println!("Shuffle line 1");
 *       println!("Shuffle line 2");
 *       println!("Shuffle line 3");
 *       #[shufflecase]
 *       println!("Shuffle line 4");
 *       println!("Shuffle line 5");
 *       #[shufflecase]
 *       println!("Shuffle line 6");
 *   }
 *
 * Trying to register a proc macro for shufflecase produces an error complaining that it's not
 * possible and to see a github issue for more information.
 * That leads down a rabbit hole of issues, stabilization, proc_macro hygiene and functionality
 * rewrites, a total mess.
 * But the end result is that no, it's not supported, not likely to be added any time soon, tough
 * luck.
 * Meaning, if we want to have this kind of functionality, another approach may be required.
 *
 * Few ideas:
 *  - Run this stuff at a build script level, automatically preprocess the entire file prior to
 *  compilation
 *  - Custom preprocessor (which honestly could still be Rust), that runs prior to compilation
 *  - Simple preprocessor that does string parsing style replacement
 *
 * Main question is how that preprocessor would work
 * Do we call it from a build script level?
 * Can build scripts actually modify code?
 * Can build scripts remove existing files from compilation? (Modify a copy, and ignore the
 * original)
 * Or do we have to hook it into cargo separately, like as an entire foreign application that runs
 * prior to "cargo build"?
 */

pub fn obfuscate(input: &String) -> String {
    let mut input2 = syn::parse_file(&input).unwrap();

    //eprintln!("INPUT: {:#?}", input2);
    //eprintln!("INFORMAT: {}", prettyplease::unparse(&input2));

    let mut shuf = ExprShuffle { list: vec![] };
    ExprShuffle::visit_file(&mut shuf, &input2);
    shuf.list.shuffle(&mut OsRng);
    ExprShuffle::visit_file_mut(&mut shuf, &mut input2);
    StrReplace.visit_file_mut(&mut input2);

    //eprintln!("OUTPUT: {:#?}", input2);
    //eprintln!("OUTFORMAT: {}", prettyplease::unparse(&input2));

    prettyplease::unparse(&input2)
}

pub fn generate_temp_folder_name(name: Option<&str>) -> Utf8PathBuf {
    let mut output = Utf8PathBuf::from_path_buf(env::temp_dir()).unwrap();
    output.push(name.unwrap_or(".r2d2_build_dir"));
    output
}

//TODO: Only copy differences with hashes/mtime checks
//TODO: This needs to be optimized and cleaned up
//TODO: Fix the error checking
pub fn copy_dir(from: &Utf8PathBuf, to: &Utf8PathBuf, skip_obfuscate: bool) -> io::Result<()> {
    let files: Vec<_> = WalkDir::new(from)
        .into_iter()
        .filter_entry(|e| {
            !e.file_name()
                .to_str()
                .map(|s| s.starts_with("."))
                .unwrap_or(false)
        })
        .collect();

    if files.iter().all(|e| !e.is_ok()) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "Some files can't be accessed",
        ));
    }

    let (dirs, files): (Vec<Utf8PathBuf>, Vec<Utf8PathBuf>) = files
        .into_iter()
        .map(|e| {
            Utf8PathBuf::from(
                Utf8Path::from_path(e.unwrap().path())
                    .unwrap()
                    .strip_prefix(&from.to_string())
                    .unwrap(),
            )
        })
        .filter(|path| !path.to_string().is_empty() && !path.to_string().starts_with("target/"))
        .partition(|e| e.is_dir());

    for dir in dirs {
        let dest_dir = to.as_std_path().join(dir);
        DirBuilder::new().recursive(true).create(&dest_dir)?;
    }

    for file in files {
        let dest_file = Utf8PathBuf::from(to).join(&file);
        let src_file = Utf8PathBuf::from(from).join(&file);

        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest_file)?;

        if file.extension().unwrap_or_default().eq("rs") && !skip_obfuscate {
            let contents = fs::read_to_string(src_file)?;
            let obfuscated = obfuscate(&contents);
            fs::write(dest_file, &obfuscated)?;
        } else {
            fs::copy(src_file, dest_file)?;
        }
    }

    Ok(())
}

pub struct SourceInformation {
    pub workspace_root: Utf8PathBuf,
    pub target_dir: Utf8PathBuf,
}

pub fn get_src_dir() -> SourceInformation {
    let metadata = MetadataCommand::new().exec().unwrap();
    SourceInformation {
        workspace_root: metadata.workspace_root,
        target_dir: metadata.target_directory,
    }
}
