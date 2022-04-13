#![allow(unused_imports)]
use goblin::{error, pe};
use proc_macro2::TokenStream;
use quote::*;
use rand;
use rand::distributions::Uniform;
use rand::prelude::*;
use rand::rngs::OsRng;
use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;

use crate::shatter::ShatterCondition;

//Workaround to self obfuscate (since we can't add ourselves as a dependency)
#[allow(unused_imports)]
use crate as r2d2;

pub fn generate_anti_debug_check() -> ShatterCondition {
    let setup = quote! {};
    let check = quote! {
        unsafe {
            r2d2::windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent().as_bool()
        }
    };
    ShatterCondition { setup, check }
}

pub fn generate_integrity_check() -> ShatterCondition {
    let setup = quote! {};
    let check = quote! { false };
    ShatterCondition { setup, check }
}
