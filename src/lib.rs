use camino::Utf8Path;
use camino::Utf8PathBuf;
use cargo_metadata::{Metadata, MetadataCommand};
use std::env;
use std::fs;
use std::fs::DirBuilder;
use std::fs::OpenOptions;
use std::io;
use std::io::ErrorKind;
use std::process::{Command, Output, Stdio};
use walkdir::WalkDir;

//Public modules referenced in generated code
pub use generic_array;
pub use digest;
pub use rand;
pub use rand::prelude::*;
pub use rand::rngs::OsRng;
pub use subtle;
pub use goblin;

#[cfg(target_os = "windows")]
pub use windows;

//Grab our submodules
pub mod crypto;
mod shuffle;
mod strencrypt;
mod shatter;
mod parse;
//Import symbols from those submodules
use crate::shuffle::*;
use crate::strencrypt::*;
use crate::shatter::*;

//Workaround to self obfuscate (since we can't add ourselves as a dependency)
#[allow(unused_imports)]
use crate as r2d2;

/*
 * Plan for shatter handling
 * Wait until Rust 1.59, when inline asm should be stabilized
 * Rely on subtle crate for assert checks in false branches
 * asm boundary as an optimization barrier
 * Probably find a nice way of generating arbitrary asm opcodes for junk creation
 * Can just splice them in every other statement in the function
 * May even want to consider adding in threading for kicks
 * Literally just spawn a thread, run that single line of code, then join the thread
 * May not be viable, but it'd be hilarious spawning tons of threads constantly, I bet it'd be
 * awful to RE
 */

/*
 * Plan for call site obfuscation
 * libloading has a "self" function call in the unix/windows specific subsections
 * Can use that to try and get some DLL callbacks for function calls
 * There's also an export_name attribute you can use to rename things for exporting
 * And also another one for section selection
 * So I can totally mess around with creating a ton of garbage ELF sections, or renaming the
 * exported function when called via DLL
 *
 * There's also the possibility of raw function pointer obfuscation
 * Rather than dealing with dlsym for it, just using plain old indirection
 * Found a stack overflow answer that mentioned how to call an arbitrary address (in the context of
 * OS code)
 * Basically, cast the thing as a *const (), which is a void pointer IIRC
 * Then use the almight mem::transmute to transform that into a callable function
 * Definitely needs to be checked and confirmed
 * I'm especially skeptical of ABI boundaries and Rust types working here
 *
 * It'd be a guaranteed problem with the DLL thing, so function pointer calculation would be nicer
 * to have
 * But how would arguments work here?
 * I'm also worried about generic functions too
 * Lot of ways for it to go wrong and shit itself
 * But being able to decrypt a memory address at runtime to call a function would be hilariously
 * sick
 */

/*
 * There is an unstable API in rust for grabbing VTables and creating fat pointers with them
 * It's nowhere close to being standardized, but it's something to watch out for
 * Encrypting VTables would be amazing
 * It's called ptr_metadata, something to keep an eye out for
 */

pub fn obfuscate(input: &String) -> (String, Shatter) {
    let mut input2 = syn::parse_file(&input).unwrap();

    //eprintln!("INPUT: {:#?}", input2);
    //eprintln!("INFORMAT: {}", prettyplease::unparse(&input2));

    shuffle(&mut input2);
    encrypt_strings(&mut input2);
    let shatter = shatter(&mut input2);

    //eprintln!("OUTPUT: {:#?}", input2);
    //eprintln!("OUTFORMAT: {}", prettyplease::unparse(&input2));

    (prettyplease::unparse(&input2), shatter)
}

pub fn generate_temp_folder_name(name: Option<&str>) -> Utf8PathBuf {
    let mut output = Utf8PathBuf::from_path_buf(env::temp_dir()).unwrap();
    output.push(name.unwrap_or(".r2d2_build_dir"));
    output
}

pub fn obfuscate_dir(dir: &Utf8PathBuf) -> io::Result<Vec<Shatter>> {
    //WalkDir filter_entry will prevent the directory from being touched, so have to filter
    //manually

    let mut shatter_states: Vec<Shatter> = Vec::new();

    for file in WalkDir::new(dir) {
        let file_path = file?.into_path();
        if file_path.to_str().unwrap_or_default().ends_with(".rs") {
            let contents = fs::read_to_string(&file_path)?;
            let (obfuscated, shatter_state) = obfuscate(&contents);
            shatter_states.push(shatter_state);
            fs::write(&file_path, &obfuscated)?;
        }
    }
    Ok(shatter_states)
}

//TODO: Only copy differences with hashes/mtime checks
//TODO: This needs to be optimized and cleaned up
//TODO: Fix the error checking
pub fn copy_dir(from: &Utf8PathBuf, to: &Utf8PathBuf) -> io::Result<()> {
    let files: Vec<_> = WalkDir::new(from)
        .into_iter()
        .filter_entry(|e| {
            !e.file_name()
                .to_str()
                .map(|s| s.starts_with("."))
                .unwrap_or(false)
        })
        .collect();

    if files.iter().all(|e| !e.is_ok()) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "Some files can't be accessed",
        ));
    }

    let (dirs, files): (Vec<Utf8PathBuf>, Vec<Utf8PathBuf>) = files
        .into_iter()
        .map(|e| {
            Utf8PathBuf::from(
                Utf8Path::from_path(e.unwrap().path())
                    .unwrap()
                    .strip_prefix(&from.to_string())
                    .unwrap(),
            )
        })
        .filter(|path| !path.to_string().is_empty() && !path.to_string().starts_with("target/"))
        .partition(|e| e.is_dir());

    for dir in dirs {
        let dest_dir = to.as_std_path().join(dir);
        DirBuilder::new().recursive(true).create(&dest_dir)?;
    }

    for file in files {
        let dest_file = Utf8PathBuf::from(to).join(&file);
        let src_file = Utf8PathBuf::from(from).join(&file);

        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest_file)?;

        fs::copy(src_file, dest_file)?;
    }

    Ok(())
}

pub struct SourceInformation {
    pub workspace_root: Utf8PathBuf,
    pub target_dir: Utf8PathBuf,
    //I know this isn't proper, but the logic is nontrivial and I want this to work before it's
    //clean
    pub metadata: Metadata,
}

pub fn get_src_dir() -> SourceInformation {
    let metadata = MetadataCommand::new().exec().unwrap();
    SourceInformation {
        workspace_root: metadata.workspace_root.clone(),
        target_dir: metadata.target_directory.clone(),
        metadata,
    }
}

pub struct R2D2Config<'a> {
    pub dest_name: Option<&'a str>,
    pub cargo_args: Option<Vec<&'a str>>,
    pub need_run: bool,
    pub need_obfuscate: bool,
    pub obfuscate_dir: Option<&'a str>,
    pub stream_output: bool,
}

pub fn build(config: &R2D2Config) -> io::Result<Output> {
    let src = get_src_dir();
    let mut dest = generate_temp_folder_name(config.dest_name);

    if let Ok(_) = std::fs::metadata(&dest) {
        //Clean up the folder if it already exists
        let _ = fs::remove_dir_all(&dest);
    }

    DirBuilder::new().recursive(true).create(&dest)?;

    copy_dir(&src.workspace_root, &dest)?;

    if let Some(partial) = config.obfuscate_dir {
        let mut true_dest_str = String::from(dest.as_str());
        true_dest_str.push('/');
        true_dest_str.push_str(partial);

        dest = Utf8PathBuf::from(true_dest_str);
    }

    let mut shatter_states: Vec<Shatter> = Vec::new();

    if config.need_obfuscate {
        shatter_states = obfuscate_dir(&dest)?;
    }

    let mut output: Output;

    //TODO: I really hate this duplication
    /*
     * TODO: Need to grab output as json and parse it with the metadata crate
     * That will give me artifact messages for every file the compiler generates
     * This includes paths, release/debug, and whether it's an executable
     * I can use this to search for my magic strings and replace them post compilation
     *
     * The key is Message::parse_stream in the metadata crate
     * That gives me an enum, and I want a CompilerArtifact enum variant
     * But that is a lot of work, and it's been a long day, that's for later
     */
    if let Some(cargo_args) = &config.cargo_args {
        if config.stream_output {
            output = Command::new("cargo")
                .arg("build")
                .arg("--target-dir")
                .arg(&src.target_dir)
                .args(cargo_args)
                .current_dir(&dest)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .output().unwrap();
        } else {
            output = Command::new("cargo")
                .arg("build")
                .arg("--target-dir")
                .arg(&src.target_dir)
                .args(cargo_args)
                .current_dir(&dest)
                .output().unwrap();
        }
    } else {
        if config.stream_output {
            output = Command::new("cargo")
                .arg("build")
                .arg("--target-dir")
                .arg(&src.target_dir)
                .current_dir(&dest)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .output().unwrap();
        } else {
            output = Command::new("cargo")
                .arg("build")
                .arg("--target-dir")
                .arg(&src.target_dir)
                .current_dir(&dest)
                .output().unwrap();
        }
    }


    //Post compilation
    //for shatter in shatter_states {
    //    shatter.post_compilation();
    //}
    let root_id = src.metadata.resolve.unwrap().root.unwrap();

    for pkg in src.metadata.packages {
        if pkg.id == root_id {
            eprintln!("I SURE FOUND IT {}", pkg.name);
            for target in pkg.targets {
                if target.kind.contains(&String::from("bin")) {
                    eprintln!("E-GADS a binary called {}", target.name);
                    eprintln!("I expect my binary at {}\\{}", src.target_dir, target.name);
                }
            }
        }
    }

    if let Some(cargo_args) = &config.cargo_args {
        if config.need_run {
            //TODO: Need to double check that the run command doesn't also rebuild after
            //post-compilation
            output = Command::new("cargo")
                .arg("run")
                .arg("--target-dir")
                .arg(&src.target_dir)
                .args(cargo_args)
                .current_dir(&dest)
                .output().unwrap();
        }
    } else {
        if config.need_run {
            //TODO: Need to double check that the run command doesn't also rebuild after
            //post-compilation
            output = Command::new("cargo")
                .arg("run")
                .arg("--target-dir")
                .arg(&src.target_dir)
                .current_dir(&dest)
                .output().unwrap();
        }
    }

    Ok(output)
}

