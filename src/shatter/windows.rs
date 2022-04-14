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
use crate::crypto::{self, hash};

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
        let name = section.name().unwrap_or_default();
        if name.is_empty() {
            continue
        }

        if (section.characteristics & pe::section_table::IMAGE_SCN_CNT_CODE) != 0 {
            eprintln!("Section {name} has executable code in it");
            eprintln!("Section details {section:#x?}");

            let base = pe.image_base;
            let size = section.virtual_size;
            let addr = (base as *const u8).add(section.virtual_address as usize);

            eprintln!("What do we have 0x{base:x}, 0x{size:x}, {addr:#?}");

            let text_slice = &*ptr::slice_from_raw_parts(addr, size as usize);

            //let (hash, salt) = crypto::hash::<crypto::Blake2b512>(text_slice, true);

            //eprintln!("Hash {hash:x?}");
            //eprintln!("Salt {salt:x?}");
        }
    }
    //eprintln!("Did we get it {pe:#?}");
}

pub fn generate_integrity_check() -> ShatterCondition {
    //unsafe {
    //    test_pe_inspection();
    //}

    //TODO: Initialize this outside of the quote
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    //Stand-in for magic hash value to be replaced post compilation
    let hash = [0xabu8; 64];

    let setup = quote! {
        let mut calculated_hash: Vec<u8> = Vec::new();

        let target_hash = vec![#(#hash),*];
        let salt = vec![#(#salt),*];

        unsafe {
            let null_pcstr = r2d2::windows::core::PCSTR(::std::ptr::null());
            let real_handle = r2d2::windows::Win32::System::LibraryLoader::GetModuleHandleA(null_pcstr).0;
            let handle = real_handle as *const u8;
            assert!(!handle.is_null());

            eprintln!("Test {handle:#?}");

            let path = ::std::env::current_exe().unwrap();
            let total_size = ::std::fs::metadata(path).unwrap().len();

            eprintln!("Our file size is {total_size}");

            let header_slice = &*::std::ptr::slice_from_raw_parts(handle, total_size as usize);
            //Need to explicitly disable rva resolution since filenames don't exist in memory
            let opts = r2d2::goblin::pe::options::ParseOptions {
                resolve_rva: false,
            };
            let pe: r2d2::goblin::pe::PE = r2d2::goblin::pe::PE::parse_with_opts(header_slice, &opts).unwrap();

            for section in pe.sections {
                let name = section.name().unwrap_or_default();
                if name.is_empty() {
                    continue
                }

                if (section.characteristics & r2d2::goblin::pe::section_table::IMAGE_SCN_CNT_CODE) != 0 {
                    eprintln!("Section {name} has executable code in it");
                    eprintln!("Section details {section:#x?}");

                    let base = pe.image_base;
                    let size = section.virtual_size;
                    let addr = (base as *const u8).add(section.virtual_address as usize);

                    eprintln!("What do we have 0x{base:x}, 0x{size:x}, {addr:#?}");

                    let text_slice = &*::std::ptr::slice_from_raw_parts(addr, size as usize);

                    calculated_hash = r2d2::crypto::hash::<r2d2::crypto::Blake2b512>(text_slice, Some(&salt));
                    break;
                }
            }
        }

        eprintln!("Salt {salt:x?}");
        eprintln!("Target {target_hash:x?}");
        eprintln!("Actual {calculated_hash:x?}");
        eprintln!("");
    };
    let check = quote! { false };
    ShatterCondition { setup, check }
}
