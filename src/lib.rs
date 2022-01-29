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
use rand::rngs::OsRng;
use rand::RngCore;
use std::convert::TryInto;
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

        let output = quote! {
            let result = r2d2::decrypt_memory::<::chacha20poly1305::XChaCha20Poly1305>(r2d2::MemoryEncryptionCtx {
                key: (::generic_array::arr![u8; #(#key),*]) as ::aead::Key::<::chacha20poly1305::XChaCha20Poly1305>,
                nonce: (::generic_array::arr![u8; #(#nonce),*]) as ::aead::Nonce::<::chacha20poly1305::XChaCha20Poly1305>,
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
}

struct ExprShuffle<'ast> {
    list: Vec<&'ast Expr>,
}

impl<'ast> Visit<'ast> for ExprShuffle<'ast> {
    fn visit_expr(&mut self, node: &'ast Expr) {
        match node {
            Expr::Array(expr) => {
                if !expr.attrs.is_empty() {
                    for attr in &expr.attrs {
                        if let Some(ident) = attr.path.get_ident() {
                            if ident.to_string() == "MyShuffleAttr" {
                                self.list.push(&node);
                            }
                        }
                    }
                }
            }
            Expr::Assign(expr) => if !expr.attrs.is_empty() {},
            Expr::AssignOp(expr) => if !expr.attrs.is_empty() {},
            Expr::Async(expr) => if !expr.attrs.is_empty() {},
            Expr::Await(expr) => if !expr.attrs.is_empty() {},
            Expr::Binary(expr) => if !expr.attrs.is_empty() {},
            Expr::Block(expr) => if !expr.attrs.is_empty() {},
            Expr::Box(expr) => if !expr.attrs.is_empty() {},
            Expr::Break(expr) => if !expr.attrs.is_empty() {},
            Expr::Call(expr) => if !expr.attrs.is_empty() {},
            Expr::Cast(expr) => if !expr.attrs.is_empty() {},
            Expr::Closure(expr) => if !expr.attrs.is_empty() {},
            Expr::Continue(expr) => if !expr.attrs.is_empty() {},
            Expr::Field(expr) => if !expr.attrs.is_empty() {},
            Expr::ForLoop(expr) => if !expr.attrs.is_empty() {},
            Expr::Group(expr) => if !expr.attrs.is_empty() {},
            Expr::If(expr) => if !expr.attrs.is_empty() {},
            Expr::Index(expr) => if !expr.attrs.is_empty() {},
            Expr::Let(expr) => if !expr.attrs.is_empty() {},
            Expr::Lit(expr) => if !expr.attrs.is_empty() {},
            Expr::Loop(expr) => if !expr.attrs.is_empty() {},
            Expr::Macro(expr) => if !expr.attrs.is_empty() {},
            Expr::Match(expr) => if !expr.attrs.is_empty() {},
            Expr::MethodCall(expr) => if !expr.attrs.is_empty() {},
            Expr::Paren(expr) => if !expr.attrs.is_empty() {},
            Expr::Path(expr) => if !expr.attrs.is_empty() {},
            Expr::Range(expr) => if !expr.attrs.is_empty() {},
            Expr::Reference(expr) => if !expr.attrs.is_empty() {},
            Expr::Repeat(expr) => if !expr.attrs.is_empty() {},
            Expr::Return(expr) => if !expr.attrs.is_empty() {},
            Expr::Struct(expr) => if !expr.attrs.is_empty() {},
            Expr::Try(expr) => if !expr.attrs.is_empty() {},
            Expr::TryBlock(expr) => if !expr.attrs.is_empty() {},
            Expr::Tuple(expr) => if !expr.attrs.is_empty() {},
            Expr::Type(expr) => if !expr.attrs.is_empty() {},
            Expr::Unary(expr) => if !expr.attrs.is_empty() {},
            Expr::Unsafe(expr) => if !expr.attrs.is_empty() {},
            Expr::While(expr) => if !expr.attrs.is_empty() {},
            Expr::Yield(expr) => if !expr.attrs.is_empty() {},
            _ => {}
        }
        // Delegate to the default impl to visit nested expressions.
        visit::visit_expr(self, node);
    }
}
impl<'ast> VisitMut for ExprShuffle<'ast> {
    fn visit_expr_mut(&mut self, node: &mut Expr) {
        //TODO: This is insane, will not work, needs fixing
        if let Expr::Lit(expr) = &node {
            if !expr.attrs.is_empty() {
                node.clone_from(self.list[0]);
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

    StrReplace.visit_file_mut(&mut input2);

    //eprintln!("OUTPUT: {:#?}", input2);
    //eprintln!("OUTFORMAT: {}", prettyplease::unparse(&input2));

    prettyplease::unparse(&input2)
}
