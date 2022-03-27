use proc_macro2::TokenStream;
use quote::*;
use rand;
use rand::prelude::*;
use rand::rngs::OsRng;
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

struct Shatter {
    inside_unsafe_block: bool,
}

impl Shatter {
    fn generate_shatter_statement(&self) -> Vec<Stmt> {
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

        let body_content = quote! {
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
                let #cond_ident = r2d2::subtle::Choice::from(0u8);
                let #result_ident = bool::from(#cond_ident);
                if #result_ident {
                    #body
                }
            }
        };
        let parsed = syn::parse2::<Block>(tokens).unwrap();
        parsed.stmts
    }
}

impl VisitMut for Shatter {
    fn visit_block_mut(&mut self, block: &mut Block) {
        let mut shattered_stmts: Vec<Stmt> = Vec::new();

        for stmt in &mut block.stmts {
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
                            _ => true,
                        }
                    }
                    Expr::Return(_) => false,
                    Expr::Yield(_) => false,
                    _ => true,
                },
            };
            shattered_stmts.push(stmt.clone());
            if !can_shatter {
                continue;
            }
            //TODO: This is where we can add a random chance to add shatter statement
            if true {
                shattered_stmts.extend_from_slice(&self.generate_shatter_statement());
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
