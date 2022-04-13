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
            //let addr = base as *const u8 + section.virtual_address as *const u8;

            eprintln!("What do we have 0x{base:x}, 0x{size:x}, {addr:#?}");


            let mut test_contents = [0u8; 0x100];
            std::ptr::copy_nonoverlapping(addr, test_contents.as_mut_ptr(), 0x100);

            eprintln!("Our starting text contents {test_contents:x?}");
        }
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
