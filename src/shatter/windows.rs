#![allow(unused_imports)]
use goblin::pe::header::*;
use goblin::pe::optional_header::*;
use goblin::pe::options::ParseOptions;
use goblin::pe::PE;
use goblin::{error, pe};
use proc_macro2::TokenStream;
use quote::*;
use rand;
use rand::distributions::Uniform;
use rand::prelude::*;
use rand::rngs::OsRng;
use scroll::{Pread, Pwrite};
use std::env;
use std::fs;
use std::mem::{self, size_of};
use std::ptr;
use windows::core::*;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::GetFileSizeEx;
use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use camino::Utf8PathBuf;
use std::collections::HashMap;
use std::cmp;

use crate::crypto::{self, hash};
use crate::shatter::{self, generate_unique_ident, IntegrityCheckType, IntegrityCheck, ShatterCondition};

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
    let opts = ParseOptions { resolve_rva: false };
    let pe: PE = PE::parse_with_opts(header_slice, &opts).unwrap();

    for section in pe.sections {
        let name = section.name().unwrap_or_default();
        if name.is_empty() {
            continue;
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

fn find_subsequence<T>(haystack: &[T], needle: &[T]) -> Option<usize>
    where for<'a> &'a [T]: PartialEq
{
    haystack.windows(needle.len()).position(|window| window == needle)
}

pub fn integrity_check_post_compilation(path: &Utf8PathBuf, checks: &Vec<IntegrityCheck>) {
    let mut contents = fs::read(path).unwrap();

    eprintln!("What's the data like? {}", contents.len());

    //Need to explicitly disable rva resolution since filenames don't exist in memory
    //let opts = ParseOptions { resolve_rva: false };
    //TODO: Make a generic API that toggles resolve_rva based on memory vs disk parsing
    //Grab the slice out of it easily without all this duplication
    let opts = ParseOptions { resolve_rva: true };
    let pe: PE = PE::parse_with_opts(&contents, &opts).unwrap();

    let mut text_start: usize = 0;
    let mut text_len: usize = 0;
    let mut data_start: usize = 0;
    let mut data_len: usize = 0;
    let mut text_slice: Vec<u8> = Vec::new();
    let mut data_slice: Vec<u8> = Vec::new();

    for section in pe.sections {
        let name = section.name().unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        //eprintln!("Section {name} has initialized data in it");
        //eprintln!("Section details {section:#x?}");

        let addr = section.pointer_to_raw_data as usize;
        /*
         * Section sizing is different between memory and on-disk
         * This means that if we want the hashes to line up for both execution and
         * post-compilation, we need to limit the sizes to a shared subset that both will have
         * valid access to.
         * This will leave a few of the trailing bytes of the section unhashed and therefore
         * modifiable, but that's just gotta be something we live with
         */
        let size = cmp::min(section.virtual_size, section.size_of_raw_data) as usize;

        //eprintln!("Section name {name} with size {size}");
        let mut section_slice = &mut contents[addr..addr+size];

        //if (section.characteristics & pe::section_table::IMAGE_SCN_CNT_CODE) != 0 {
        if name == ".text" {
            eprintln!("Physical {} Virtual {}", section.size_of_raw_data, section.virtual_size);
            text_slice = Vec::from(section_slice);
            text_start = addr;
            text_len = size;
        //} else if (section.characteristics & pe::section_table::IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 {
        } else if name == ".rdata" {
            data_slice = Vec::from(section_slice);
            data_start = addr;
            data_len = size;
        }
    }

    for check in checks {
        match check.check_type {
            IntegrityCheckType::ALL => {
                let offset = find_subsequence(&data_slice, &check.hash).unwrap();
                let real_hash = crypto::hash::<crypto::Blake2b512>(&text_slice, Some(&check.salt));
                eprintln!("Post Calculating against hash of len {}", text_slice.len());

                contents[data_start+offset..data_start+offset+64].copy_from_slice(&real_hash);

                eprintln!("Hash {:x?}", &check.hash);
                eprintln!("REAL {real_hash:x?}");
                eprintln!("Salt {:x?}", &check.salt);


            }
            //Currently we don't have any other kinds of hashing checks
        }
    }

    fs::write(path, contents).unwrap();
}

pub fn generate_integrity_check() -> (ShatterCondition, IntegrityCheck) {
    //unsafe {
    //    test_pe_inspection();
    //}

    //TODO: Initialize this outside of the quote
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    //Magic random value to be replaced post compilation with the real hash
    let mut hash = [0u8; 64];
    OsRng.fill_bytes(&mut hash);

    let static_ident = generate_unique_ident();
    let hash_size = 64usize;

    let setup = quote! {
        #[used]
        #[link_section = ".rdata"]
        #[allow(non_upper_case_globals)]
        static #static_ident: [u8; #hash_size] = [#(#hash),*];

        let salt = vec![#(#salt),*];

        let mut calculated_hash: Vec<u8> = Vec::new();

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

                //if (section.characteristics & r2d2::goblin::pe::section_table::IMAGE_SCN_CNT_CODE) != 0 {
                if name == ".text" {
                    //eprintln!("Section {name} has executable code in it");
                    //eprintln!("Section details {section:#x?}");

                    let base = pe.image_base;
                    /*
                     * Section sizing is different between memory and on-disk
                     * This means that if we want the hashes to line up for both execution and
                     * post-compilation, we need to limit the sizes to a shared subset that both will have
                     * valid access to.
                     * This will leave a few of the trailing bytes of the section unhashed and therefore
                     * modifiable, but that's just gotta be something we live with
                     */
                    let size = ::std::cmp::min(section.virtual_size, section.size_of_raw_data) as usize;
                    let addr = (base as *const u8).add(section.virtual_address as usize);

                    //eprintln!("What do we have 0x{base:x}, 0x{size:x}, {addr:#?}");

                    let text_slice = &*::std::ptr::slice_from_raw_parts(addr, size as usize);

                    eprintln!("Calculating against hash of len {}", text_slice.len());
                    eprintln!("Physical {} Virtual {}", section.size_of_raw_data, section.virtual_size);

                    calculated_hash = r2d2::crypto::hash::<r2d2::crypto::Blake2b512>(text_slice, Some(&salt));
                    break;
                }
            }
        }

        eprintln!("Salt {salt:x?}");
        eprintln!("Target {:x?}", #static_ident);
        eprintln!("Actual {calculated_hash:x?}");
        eprintln!("");
    };
    let check = quote! { false };

    (
        ShatterCondition { setup, check },
        IntegrityCheck {
            check_type: IntegrityCheckType::ALL,
            hash: Vec::from(hash),
            salt: Vec::from(salt)
        }
    )
}
