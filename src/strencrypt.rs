use quote::*;
use syn::spanned::Spanned;
use syn::visit_mut::*;
use syn::*;

//Needed for the quote memory encryption routines to resolve
use crate::crypto::*;
use crate::parse::*;
//Workaround to self obfuscate (since we can't add ourselves as a dependency)
#[allow(unused_imports)]
use crate as r2d2;

struct MemEncCtx {
    ctx: MemoryEncryptionCtx<XChaCha20Poly1305>,
    needs_owned_str: bool,
}

impl ToTokens for MemEncCtx {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let key = &self.ctx.key;
        let nonce = &self.ctx.nonce;
        let ciphertext = &self.ctx.ciphertext;
        let output: proc_macro2::TokenStream;

        if self.needs_owned_str {
            /*
             * let x = "foobar";
             * println!("{}", x);
             *
             * This snippet requires special handling since the temporary decrypted string goes out
             * of scope after decryption, so we need to return a string object rather than a &str
             * This could theoretically still have issues with explicit typing, but we'll cross
             * that bridge when we get there
             */
            output = quote! {
                let result = r2d2::crypto::decrypt_memory::<r2d2::crypto::chacha20poly1305::XChaCha20Poly1305>(r2d2::crypto::MemoryEncryptionCtx {
                    key: (r2d2::generic_array::arr![u8; #(#key),*]) as r2d2::crypto::aead::Key::<r2d2::crypto::chacha20poly1305::XChaCha20Poly1305>,
                    nonce: (r2d2::generic_array::arr![u8; #(#nonce),*]) as r2d2::crypto::aead::Nonce::<r2d2::crypto::chacha20poly1305::XChaCha20Poly1305>,
                    ciphertext: ::std::vec![#(#ciphertext),*],
                });
                ::std::string::String::from_utf8(result).unwrap()
            };
        } else {
            output = quote! {
                let result = r2d2::crypto::decrypt_memory::<r2d2::crypto::chacha20poly1305::XChaCha20Poly1305>(r2d2::crypto::MemoryEncryptionCtx {
                    key: (r2d2::generic_array::arr![u8; #(#key),*]) as r2d2::crypto::aead::Key::<r2d2::crypto::chacha20poly1305::XChaCha20Poly1305>,
                    nonce: (r2d2::generic_array::arr![u8; #(#nonce),*]) as r2d2::crypto::aead::Nonce::<r2d2::crypto::chacha20poly1305::XChaCha20Poly1305>,
                    ciphertext: ::std::vec![#(#ciphertext),*],
                });
                ::std::string::String::from_utf8(result).unwrap().as_str()
            };
        }

        tokens.append_all(output);
    }
}

struct StrReplace;

/*
 * The choice of Self::visit_*_mut vs visit_mut::visit_*_mut is important here
 * Some choices will result in breakage by not encrypting
 * Others will create a recursive loop exhausting the stack
 *
 * NOTE: DO NOT MODIFY WITHOUT TESTING AND VERIFICATION
 */
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
            if let Lit::Str(s) = &parsed.format_string.lit {
                if s.value().contains("{") {
                    //Don't mess with format strings that aren't trivial
                    can_encrypt = false;
                }
            } else {
                panic!("Format string is not a string literal!");
            }

            if parsed.positional_args.is_empty() && parsed.named_args.is_empty() && can_encrypt {
                //Change the string literal to ("{}", "str") to allow block expression replacement
                let span = parsed.format_string.span();

                //Store the old value as an arg
                parsed
                    .positional_args
                    .push(Expr::Lit(parsed.format_string.to_owned()));

                //Replace the format string with a trivial one
                parsed.format_string = ExprLit {
                    attrs: Vec::new(),
                    lit: Lit::Str(LitStr::new("{}", span)),
                };

                Self::visit_expr_mut(self, &mut parsed.positional_args[0]);
            } else {
                parsed
                    .positional_args
                    .iter_mut()
                    .for_each(|mut e| Self::visit_expr_mut(self, &mut e));
            }
            node.tokens = parsed.to_token_stream();
        }
        // Delegate to the default impl to visit nested macros.
        visit_mut::visit_macro_mut(self, node);
    }

    fn visit_expr_mut(&mut self, node: &mut Expr) {
        /*
         * Skip function call expressions
         * This is a case of lifetime scoping problems
         * Given a function foo("hello"), only a String type would support decryption
         * If the function takes a &str, the temporary will go out of scope and fail to compile
         * I'm not about to become a linker, so this has to be skipped
         * Best case is to limit/audit string literals to prevent this case
         */
        let must_skip = match &node {
            Expr::Call(_) => true,
            Expr::MethodCall(_) => true,
            _ => false,
        };

        if must_skip {
            return;
        }

        if let Expr::Lit(expr) = &node {
            if let Lit::Str(s) = &expr.lit {
                let mem_ctx = MemEncCtx {
                    ctx: encrypt_memory::<XChaCha20Poly1305>(s.value().as_bytes()),
                    needs_owned_str: false,
                };
                let output = quote! {
                    {
                        #mem_ctx
                    }
                };
                let output = syn::parse2::<ExprBlock>(output).unwrap();
                *node = Expr::Block(output);
                return;
            } else if let Lit::ByteStr(s) = &expr.lit {
                let mem_ctx = MemEncCtx {
                    ctx: encrypt_memory::<XChaCha20Poly1305>(&s.value()),
                    needs_owned_str: false,
                };
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
        Self::visit_expr_mut(self, &mut node.body);
    }

    fn visit_item_const_mut(&mut self, _node: &mut ItemConst) {
        /*
         * Skip all constant expressions since we can't decrypt those
         * Function intentionally left blank
         */
    }

    fn visit_local_mut(&mut self, node: &mut Local) {
        if let Some(init) = &node.init {
            if let Expr::Lit(expr) = &*init.1 {
                if let Lit::Str(s) = &expr.lit {
                    /*
                     * Skip let assignments with an explicit reference type
                     * This is fine for string literals due to static lifetime
                     * Decryption doesn't have a static lifetime, so an explicit reference storage
                     * will run into object lifetime issues
                     */
                    if let Pat::Type(ty) = &node.pat {
                        if let Type::Reference(_) = *ty.ty {
                            return;
                        }
                    }

                    let mem_ctx = MemEncCtx {
                        ctx: encrypt_memory::<XChaCha20Poly1305>(s.value().as_bytes()),
                        needs_owned_str: true,
                    };
                    let output = quote! {
                        {
                            #mem_ctx
                        }
                    };
                    let output = syn::parse2::<ExprBlock>(output).unwrap();
                    node.init = Some((init.0, Box::new(Expr::Block(output))));
                    return;
                }
            }
        }
    }
}

pub fn encrypt_strings(input: &mut File) {
    StrReplace.visit_file_mut(input);
}
