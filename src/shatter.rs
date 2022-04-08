use proc_macro2::TokenStream;
use quote::*;
use rand;
use rand::distributions::Uniform;
use rand::prelude::*;
use rand::rngs::OsRng;
use syn::visit_mut::*;
use syn::*;

use crate::parse::*;

//Workaround to self obfuscate (since we can't add ourselves as a dependency)
#[allow(unused_imports)]
use crate as r2d2;

//All the arch backend modules
mod x86_64;

//Conditional use statements to bring the right backend into scope
//Currently use the x64 backend for x86 until we need 32-bit exclusive options
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::shatter::x86_64 as arch;

enum ShatterType {
    //Garbage code to foil static analysis tools, never executed
    STATIC,
    //Meaningless false execution paths to confuse dynamic analysis, may execute, ending in a crash
    DYNAMIC,
}

enum ConditionType {
    //Just a fancy "if false" condition
    FALSE,
    //Anti-debug check logic
    DEBUG,
    //Verify the in-memory integrity of the executable
    INTEGRITY,
    //Kill date verification (super simple, enforced by integrity checks)
    KILLDATE,
}

struct Shatter {
    inside_unsafe_block: bool,
}

struct ShatterCondition {
    setup: TokenStream,
    check: TokenStream,
}

impl Shatter {

    fn generate_false_condition(&self) -> ShatterCondition {
        let cond_ident = format_ident!(
            "cond_{}{}{}{}",
            OsRng.next_u64(),
            OsRng.next_u64(),
            OsRng.next_u64(),
            OsRng.next_u64()
        );
        let result_ident = format_ident!(
            "result_{}{}{}{}",
            OsRng.next_u64(),
            OsRng.next_u64(),
            OsRng.next_u64(),
            OsRng.next_u64()
        );
        let setup = quote! {
            let #cond_ident = r2d2::subtle::Choice::from(0u8);
            let #result_ident = bool::from(#cond_ident);
        };
        let check = quote! {
            #result_ident
        };
        ShatterCondition { setup, check }
    }

    fn generate_branch_condition(&self) -> ShatterCondition {
        if true {
            return self.generate_false_condition();
        }
        unimplemented!();
    }

    fn generate_garbage_asm(&self) -> TokenStream {
        let mut garbage: Vec<u8> = arch::generate_partial_instruction();

        if garbage.is_empty() {
            //Fallback to random bytes
            let between = Uniform::from(32..96);
            let garbage_len: usize = between.sample(&mut OsRng);

            garbage = Vec::with_capacity(garbage_len);

            while garbage.len() < garbage_len {
                let data = OsRng.next_u64().to_ne_bytes();
                garbage.extend_from_slice(&data);
            }
            //Truncate in case the loop over extended the vec
            garbage.truncate(garbage_len);
        }

        let mut asm_byte_strings = TokenStream::new();

        for byte in garbage {
            let byte_string = format!(".byte 0x{:X};", byte);
            asm_byte_strings.extend(quote! {
                #byte_string,
            });
        }

        let body_content = quote! {
            std::arch::asm!(
                //This expansion has a trailing comma
                #asm_byte_strings
                //Not currently doing any explicit register clobbering here, but it's garbage, so
                //who cares
                clobber_abi("C"),
            );
        };
        body_content
    }

    fn generate_rabbit_hole(&self) -> TokenStream {
        let rabbit_hole = arch::generate_rabbit_hole();
        //TODO: Have non-asm rabbit holes, and randomly choose between asm and generic here
        rabbit_hole
    }

    fn generate_shatter_statement(&self, shatter_type: ShatterType) -> Vec<Stmt> {
        let body_content = match shatter_type {
            ShatterType::STATIC => self.generate_garbage_asm(),
            ShatterType::DYNAMIC => self.generate_rabbit_hole(),
        };

        let body: TokenStream;
        if self.inside_unsafe_block {
            body = quote! {
                #body_content
            };
        } else {
            body = quote! {
                unsafe {
                    #body_content
                }
            };
        }
        let tokens = quote! {
            {
                #body
            }
        };
        let parsed = syn::parse2::<Block>(tokens).unwrap();
        parsed.stmts
    }

    fn inject_branch(&self) -> Vec<Stmt> {
        let ShatterCondition { setup, check } = self.generate_branch_condition();
        let body = self.generate_shatter_statement(ShatterType::STATIC);
        let tokens = quote! {
            {
                #setup
                if #check {
                    #(#body)*
                }
            }
        };
        let parsed = syn::parse2::<Block>(tokens).unwrap();
        parsed.stmts
    }

    fn convert_assert(&self, assert: Option<ExprMacro>, is_cmp: bool, is_eq: bool) -> Vec<Stmt> {
        let m = assert.unwrap();

        let condition: TokenStream;

        /*
         * We negate the conditions
         * This is replacing an assert, so an assert for a true condition means we insert garbage
         * when a false condition is present
         * We're taking the place of the failure case here
         */
        if is_cmp {
            //This is an *_eq or *_ne assert
            let parsed = m.mac.parse_body::<AssertCmpArgs>().unwrap();
            let parsed_first = parsed.first_condition;
            let parsed_second = parsed.second_condition;
            if is_eq {
                condition = quote! {
                    #parsed_first != #parsed_second
                };
            } else {
                condition = quote! {
                    #parsed_first == #parsed_second
                };
            }
        } else {
            //This is a simple assert without any equality checks
            let parsed = m.mac.parse_body::<AssertArgs>().unwrap();
            let parsed_cond = parsed.condition;
            condition = quote! {
                !(#parsed_cond)
            };
        }

        let body = self.generate_shatter_statement(ShatterType::DYNAMIC);

        let replacement = quote! {
            {
                if #condition {
                    #(#body)*
                }
            }
        };

        let parsed_replacement = syn::parse2::<Block>(replacement).unwrap();
        parsed_replacement.stmts
    }
}

impl VisitMut for Shatter {
    fn visit_block_mut(&mut self, block: &mut Block) {
        let mut shattered_stmts: Vec<Stmt> = Vec::new();

        for stmt in &mut block.stmts {
            let mut is_assert = false;
            let mut is_assert_eq = false;
            let mut is_assert_cmp = false;
            let mut assert_macro: Option<ExprMacro> = None;

            let can_shatter = match stmt {
                Stmt::Local(_) => true,
                Stmt::Item(_) => true,
                Stmt::Expr(expr) => {
                    /*
                     * Need to visit expressions since this will also affect control flow blocks
                     * Things like Match statements, while loops, if statements, all that fun stuff
                     * Without this visit, we don't shatter anything inside of any of those, which
                     * is lame
                     */
                    Self::visit_expr_mut(self, expr);
                    //Ignore Expr, we only want to shatter near expressions that have semicolons
                    false
                }
                Stmt::Semi(expr, _) => match expr {
                    //Skip break/continue/return
                    Expr::Break(_) => false,
                    Expr::Continue(_) => false,
                    Expr::Macro(expr) => {
                        let macro_path = expr
                            .mac
                            .path
                            .get_ident()
                            .map(|ident| ident.to_string())
                            .unwrap_or_default();
                        //Skip any macros that affect control flow
                        match macro_path.as_str() {
                            "compile_error" => false,
                            "panic" => false,
                            "unreachable" => false,
                            "unimplemented" => false,
                            "assert" => {
                                is_assert = true;
                                is_assert_cmp = false;
                                is_assert_eq = false;
                                assert_macro = Some(expr.to_owned());
                                true
                            }
                            "assert_eq" => {
                                is_assert = true;
                                is_assert_cmp = true;
                                is_assert_eq = true;
                                assert_macro = Some(expr.to_owned());
                                true
                            }
                            "assert_ne" => {
                                is_assert = true;
                                is_assert_cmp = true;
                                is_assert_eq = false;
                                assert_macro = Some(expr.to_owned());
                                true
                            }
                            "debug_assert" => {
                                is_assert = true;
                                is_assert_cmp = false;
                                is_assert_eq = false;
                                assert_macro = Some(expr.to_owned());
                                true
                            }
                            "debug_assert_eq" => {
                                is_assert = true;
                                is_assert_cmp = true;
                                is_assert_eq = true;
                                assert_macro = Some(expr.to_owned());
                                true
                            }
                            "debug_assert_ne" => {
                                is_assert = true;
                                is_assert_cmp = true;
                                is_assert_eq = false;
                                assert_macro = Some(expr.to_owned());
                                true
                            }
                            _ => true,
                        }
                    }
                    Expr::Return(_) => false,
                    Expr::Yield(_) => false,
                    _ => true,
                },
            };
            if !is_assert {
                shattered_stmts.push(stmt.clone());
            }
            if !can_shatter {
                continue;
            }
            if is_assert {
                //Parse and convert the assert
                shattered_stmts.extend_from_slice(&self.convert_assert(
                    assert_macro,
                    is_assert_cmp,
                    is_assert_eq,
                ));
            } else {
                //TODO: This is where we can add a random chance to add shatter statement
                if true {
                    shattered_stmts.extend_from_slice(&self.inject_branch());
                }
            }
            // Delegate to the default impl to visit nested scopes.
            Self::visit_stmt_mut(self, stmt);
        }
        block.stmts = shattered_stmts;
    }

    fn visit_expr_unsafe_mut(&mut self, expr: &mut ExprUnsafe) {
        self.inside_unsafe_block = true;
        // Delegate to the default impl to visit nested scopes.
        Self::visit_block_mut(self, &mut expr.block);
        self.inside_unsafe_block = false;
    }
}

//TODO: Add configuration for conditional shatter injection
pub fn shatter(input: &mut File) {
    let mut state = Shatter {
        inside_unsafe_block: false,
    };
    Shatter::visit_file_mut(&mut state, input);
}
