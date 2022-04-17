use proc_macro2::TokenStream;
use quote::*;
use rand;
use rand::distributions::Uniform;
use rand::prelude::*;
use rand::rngs::OsRng;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use syn::spanned::Spanned;
use syn::token::Brace;
use syn::visit_mut::*;
use syn::*;
use camino::Utf8PathBuf;
use std::cmp::{Eq, PartialEq};

use crate::parse::*;

//Workaround to self obfuscate (since we can't add ourselves as a dependency)
#[allow(unused_imports)]
use crate as r2d2;

/*
 * ********************************************
 * Arch backends
 * ********************************************
 */
//x86_64
#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
use crate::shatter::x86_64 as arch;

/*
 * ********************************************
 * OS backends
 * ********************************************
 */
//Linux
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use crate::shatter::linux as os;

//Windows
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use crate::shatter::windows as os;

const DEBUG_KILLDATE_DURATION_SECS: u64 = 6000;

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

#[derive(Debug, Clone, Copy)]
pub enum IntegrityCheckType {
    //Hash every byte
    ALL,
    //TODO: Define and implement other variations like every Nth byte
}

//TODO: Make this generic over the digest used
#[derive(Debug, Clone)]
pub struct IntegrityCheck {
    pub check_type: IntegrityCheckType,
    //TODO: Use a fixed size buffer instead of a vec
    pub hash: Vec<u8>,
    pub salt: Vec<u8>,
}

pub struct Shatter {
    inside_unsafe_block: bool,
    integrity_checks: Vec<IntegrityCheck>
}

//TODO: Is it better to type check this and pay the double conversion cost?
//Debugging improper injection code is a royal pain
pub struct ShatterCondition {
    setup: TokenStream,
    check: TokenStream,
}

fn generate_unique_ident() -> proc_macro2::Ident {
    //Append a random 256 bit integer, if this ever has a collision, buy a lottery ticket!
    format_ident!(
        "var_{:x}{:x}{:x}{:x}",
        OsRng.next_u64(),
        OsRng.next_u64(),
        OsRng.next_u64(),
        OsRng.next_u64()
    )
}

impl Shatter {
    fn generate_false_condition(&mut self) -> ShatterCondition {
        let cond_ident = generate_unique_ident();
        let result_ident = generate_unique_ident();
        let setup = quote! {
            let #cond_ident = r2d2::subtle::Choice::from(0u8);
            let #result_ident = bool::from(#cond_ident);
        };
        let check = quote! {
            #result_ident
        };
        ShatterCondition { setup, check }
    }

    //TODO: Implement
    fn generate_anti_debug_check(&mut self) -> ShatterCondition {
        os::generate_anti_debug_check()
    }

    //TODO: Implement
    fn generate_integrity_check(&mut self) -> ShatterCondition {
        let (cond, check) = os::generate_integrity_check();
        self.integrity_checks.push(check);
        cond
    }

    fn generate_kill_date_check(&mut self) -> ShatterCondition {
        let epoch_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let target_date_seconds = option_env!("KILLDATE");
        let target_duration: Duration;

        if let Some(secs) = target_date_seconds {
            //Killdate was passed as a parameter
            let parsed_killdate = secs.parse::<u64>().unwrap();
            target_duration = Duration::from_secs(parsed_killdate);
            if target_duration <= epoch_now {
                //Killdate is in the past
                panic!("CANNOT USE KILLDATE IN THE PAST");
            }
        } else {
            //Killdate wasn't passed, let's use a default value for testing
            if !cfg!(debug_assertions) {
                panic!("REFUSING TO USE DEFAULT KILLDATE IN RELEASE MODE");
            }
            target_duration = epoch_now + Duration::from_secs(DEBUG_KILLDATE_DURATION_SECS);
        }

        let now_ident = generate_unique_ident();
        let target_secs = target_duration.as_secs();

        let setup = quote! {
            let #now_ident = ::std::time::SystemTime::now().duration_since(::std::time::UNIX_EPOCH).unwrap();
        };
        let check = quote! {
            #now_ident.as_secs() >= #target_secs
        };
        ShatterCondition { setup, check }
    }

    fn generate_branch_condition(&mut self) -> ShatterCondition {
        let conditions: Vec<ConditionType> = vec![
            ConditionType::FALSE,
            ConditionType::DEBUG,
            ConditionType::INTEGRITY,
            ConditionType::KILLDATE,
        ];

        let cond_type = conditions.choose(&mut OsRng).unwrap();
        match cond_type {
            ConditionType::FALSE => self.generate_false_condition(),
            ConditionType::DEBUG => self.generate_anti_debug_check(),
            ConditionType::INTEGRITY => self.generate_integrity_check(),
            ConditionType::KILLDATE => self.generate_kill_date_check(),
        }
    }

    fn generate_garbage_asm(&mut self) -> Block {
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
            {
                std::arch::asm!(
                    //This expansion has a trailing comma
                    #asm_byte_strings
                    //Not currently doing any explicit register clobbering here, but it's garbage, so
                    //who cares
                    clobber_abi("C"),
                );
            }
        };
        syn::parse2::<Block>(body_content).unwrap()
    }

    fn generate_rabbit_hole(&mut self) -> Block {
        //TODO: Have non-asm rabbit holes, and randomly choose between asm and generic here
        arch::generate_rabbit_hole()
    }

    fn generate_shatter_statement(&mut self, shatter_type: ShatterType) -> Block {
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
        syn::parse2::<Block>(tokens).unwrap()
    }

    fn inject_branch(&mut self) -> Vec<Stmt> {
        let ShatterCondition { setup, check } = self.generate_branch_condition();
        let body = self.generate_shatter_statement(ShatterType::STATIC);
        let tokens = quote! {
            {
                #setup
                if #check {
                    #body
                }
            }
        };
        let parsed = syn::parse2::<Block>(tokens).unwrap();
        parsed.stmts
    }

    fn convert_assert(&mut self, assert: ExprMacro, is_cmp: bool, is_eq: bool) -> Vec<Stmt> {
        let condition: TokenStream;

        /*
         * We negate the conditions
         * This is replacing an assert, so an assert for a true condition means we insert garbage
         * when a false condition is present
         * We're taking the place of the failure case here
         */
        if is_cmp {
            //This is an *_eq or *_ne assert
            let parsed = assert.mac.parse_body::<AssertCmpArgs>().unwrap();
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
            let parsed = assert.mac.parse_body::<AssertArgs>().unwrap();
            let parsed_cond = parsed.condition;
            condition = quote! {
                !(#parsed_cond)
            };
        }

        let parsed_condition: Box<Expr> = Box::new(syn::parse2::<Expr>(condition).unwrap());

        let body = self.generate_shatter_statement(ShatterType::DYNAMIC);

        //This is done to enforce type safety rather than relying on quote! type detection to be
        //parsed correctly
        let data = Block {
            brace_token: Brace {
                span: assert.span(),
            },
            stmts: vec![Stmt::Expr(Expr::If(ExprIf {
                attrs: Vec::new(),
                if_token: Token![if](assert.span()),
                cond: parsed_condition,
                then_branch: body,
                else_branch: None,
            }))],
        };
        data.stmts
    }

    pub fn post_compilation(&self, path: &Utf8PathBuf) {
        os::integrity_check_post_compilation(path, &self.integrity_checks);
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
                    assert_macro.unwrap(),
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
pub fn shatter(input: &mut File) -> Shatter {
    let mut state = Shatter {
        inside_unsafe_block: false,
        integrity_checks: Vec::new(),
    };
    Shatter::visit_file_mut(&mut state, input);

    state
}


