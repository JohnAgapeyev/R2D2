use quote::*;
use rand;
use rand::prelude::*;
use rand::rngs::OsRng;
use subtle::*;
use syn::visit_mut::*;
use syn::*;

//Workaround to self obfuscate (since we can't add ourselves as a dependency)
#[allow(unused_imports)]
use crate as r2d2;

//All the arch backend modules
mod x86;
mod x86_64;

//Conditional use statements to bring the right backend into scope
#[cfg(target_arch = "x86")]
use crate::shatter::x86 as arch;
#[cfg(target_arch = "x86_64")]
use crate::shatter::x86_64 as arch;

//Import all the arch backend symbols
use arch::*;

struct Shatter;

fn generate_shatter_statement() -> Vec<Stmt> {
    /*
     * Need to wrap the unsafe block in a basic block for parsing to be happy
     * We want a basic Block type, so we can fetch the vector of statements it generates
     * This is also generic enough that Rust source only solutions like kill date will work without
     * any extra parsing or logic
     */
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
    let tokens = quote! {
        {
            let #cond_ident = r2d2::subtle::Choice::from(0u8);
            let #result_ident = bool::from(#cond_ident);
            if #result_ident {
                unsafe {
                    std::arch::asm!(
                        "nop",
                        out("rax") _,
                        //out("rbx") _,
                        out("rcx") _,
                        out("rdx") _,
                        out("rsi") _,
                        out("rdi") _,
                        clobber_abi("C"),
                    );
                }
            }
        }
    };
    let parsed = syn::parse2::<Block>(tokens).unwrap();
    parsed.stmts
}

impl VisitMut for Shatter {
    fn visit_block_mut(&mut self, block: &mut Block) {
        let mut shattered_stmts: Vec<Stmt> = Vec::new();

        for stmt in &mut block.stmts {
            /*
             * TODO: Ignore any kind of break/continue/return expressions
             * Anything injected afterwords is unreachable
             * Injecting after return expressions is also a compiler error
             */
            /*
             * TODO: Detect whether we're inside an unsafe block already
             * We can skip any unsafe blocks in the shattered code, which eliminates a compiler
             * warning on the obfuscated source
             */
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
                Stmt::Semi(_, _) => true,
            };
            shattered_stmts.push(stmt.clone());
            if !can_shatter {
                continue;
            }
            //TODO: This is where we can add a random chance to add shatter statement
            if true {
                shattered_stmts.extend_from_slice(&generate_shatter_statement());
            }
            // Delegate to the default impl to visit nested scopes.
            Self::visit_stmt_mut(self, stmt);
        }
        block.stmts = shattered_stmts;
    }
}

//TODO: Add configuration for conditional shatter injection
pub fn shatter(input: &mut File) {
    Shatter.visit_file_mut(input);
}
