#![allow(unused_imports)]
use goblin::{elf, elf64, error};
use proc_macro2::TokenStream;
use quote::*;
use rand;
use rand::distributions::Uniform;
use rand::prelude::*;
use rand::rngs::OsRng;

use crate::shatter::{generate_unique_ident, ShatterCondition};

//Workaround to self obfuscate (since we can't add ourselves as a dependency)
#[allow(unused_imports)]
use crate as r2d2;

pub fn generate_anti_debug_check() -> ShatterCondition {
    //TODO: Have more than 1 and randomly choose between them
    let file_ident = generate_unique_ident();
    let reader_ident = generate_unique_ident();
    let pid_ident = generate_unique_ident();
    let line_ident = generate_unique_ident();

    /*
     * Checks for TracerPid != 0 in /proc/self/status
     */
    let setup = quote! {
        let mut #pid_ident: u64 = 0;
        let #file_ident = ::std::fs::File::open("/proc/self/status").unwrap();
        let #reader_ident = ::std::io::BufReader::new(#file_ident);

        for #line_ident in <::std::io::BufReader<::std::fs::File> as ::std::io::BufRead>::lines(#reader_ident)
            .map(|line| line.unwrap())
            .filter(|line| line.starts_with("TracerPid:"))
        {
            //10 for the length of "TracerPid:"
            let #line_ident = &#line_ident[10..].trim();
            #pid_ident = #line_ident.parse::<u64>().unwrap();
            break;
        }
    };
    let check = quote! { #pid_ident != 0 };
    ShatterCondition { setup, check }
}

pub fn generate_integrity_check() -> ShatterCondition {
    let setup = quote! {};
    let check = quote! { false };
    ShatterCondition { setup, check }
}
