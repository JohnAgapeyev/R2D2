#![allow(unused_imports)]
use goblin::{error, pe};
use goblin::pe::header::*;
use goblin::pe::optional_header::*;
use goblin::pe::PE;
use goblin::pe::options::ParseOptions;
use proc_macro2::TokenStream;
use quote::*;
use rand;
use rand::distributions::Uniform;
use rand::prelude::*;
use rand::rngs::OsRng;
use scroll::{Pread, Pwrite};
use windows::core::*;
use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Storage::FileSystem::GetFileSizeEx;
use std::ptr;
use std::mem::{self, size_of};
use std::env;
use std::fs;

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

unsafe fn test_pe_inspection() {
    let null_pcstr = PCSTR(ptr::null());
    let real_handle = GetModuleHandleA(null_pcstr).0;
    let handle = real_handle as *const u8;
    assert!(!handle.is_null());

    eprintln!("Test {handle:#?}");

    let path = env::current_exe().unwrap();
    let total_size = fs::metadata(path).unwrap().len();

    eprintln!("Our file size is {total_size}");

    let header_slice = &*ptr::slice_from_raw_parts(handle, total_size as usize);
    //Need to explicitly disable rva resolution since filenames don't exist in memory
    let opts = ParseOptions {
        resolve_rva: false,
    };
    let pe: PE = PE::parse_with_opts(header_slice, &opts).unwrap();

    for section in pe.sections {
        //Need to manually strip the trailing zero bytes for shortened section names
        let mut len = 0usize;
        for (i, b) in section.name.iter().enumerate().rev() {
            if b != &0u8 {
                len = i;
                break;
            }
        }
        //Avoid dying on stripped PE section names (I honestly wonder if this is valid)
        if len == 0 {
            continue;
        }

        //+1 due to len storing the last zero indexed valid character
        //"foo" would have a len of 2
        let s = std::string::String::from_utf8(section.name[..len+1].to_vec()).unwrap();
        eprintln!("Proper section name {s:#?}");
    }

    //eprintln!("Did we get it {pe:#?}");
}

pub fn generate_integrity_check() -> ShatterCondition {
    unsafe {
        test_pe_inspection();
    }
    let setup = quote! {};
    let check = quote! { false };
    ShatterCondition { setup, check }
}
