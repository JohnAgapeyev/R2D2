use rand::prelude::SliceRandom;
use rand::rngs::OsRng;
use syn::spanned::Spanned;
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

fn generate_shatter_statement() -> Stmt {
    unimplemented!();
}

impl VisitMut for Shatter {
    fn visit_block_mut(&mut self, block: &mut Block) {
        let mut shattered_stmts: Vec<Stmt> = Vec::new();

        for stmt in &block.stmts {
            let can_shatter = match stmt {
                Stmt::Local(_) => true,
                Stmt::Item(_) => true,
                //Ignore Expr, we only want to shatter near expressions that have semicolons
                Stmt::Semi(_, _) => true,
                _ => false,
            };
            if !can_shatter {
                continue;
            }
            shattered_stmts.push(stmt.to_owned());
            //TODO: This is where we can add a random chance to add shatter statement
            if true {
                shattered_stmts.push(generate_shatter_statement());
            }
        }
        block.stmts = shattered_stmts;
    }
}

//TODO: Add configuration for conditional shatter injection
pub fn shatter(input: &mut File) {
    Shatter.visit_file_mut(input);
}
