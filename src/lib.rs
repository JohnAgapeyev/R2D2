use camino::Utf8Path;
use camino::Utf8PathBuf;
use cargo_metadata::MetadataCommand;
use std::env;
use std::fs;
use std::fs::DirBuilder;
use std::fs::OpenOptions;
use std::io;
use std::io::ErrorKind;
use walkdir::WalkDir;

//Public modules referenced in generated code
pub use generic_array;
pub use rand;
pub use rand::prelude::*;
pub use rand::rngs::OsRng;

//Grab our submodules
pub mod crypto;
mod shuffle;
mod strencrypt;
//Import symbols from those submodules
use crate::shuffle::*;
use crate::strencrypt::*;

//Workaround to self obfuscate (since we can't add ourselves as a dependency)
#[allow(unused_imports)]
use crate as r2d2;

/*
 * Plan of attack for full encryption of strings
 * Parse as ItemFn
 * Fold on Expr objects
 * Filter/Match only on ExprLit
 * Filter out ExprLit that aren't strings
 * Replace ExprLit with ExprBlock
 * Generate ExprBlock using quote!
 * Done inside the generic fold_expr call, so we can change the enum type easily
 *
 * If we manage to get RNG output in this proc_macro execution, might not even need to worry about
 * const functions being an annoying edge case
 * Obviously wouldn't help against const function initialization of static strings
 * But for that, you can probably get away with a standard EncryptedBox<String> type move
 * Would need a test to verify that though, but also easy enough to forbid in code review
 */

/*
 * Plan for runtime string encryption
 * Need to make a wrapper type obviously
 * Almost certainly needs to implement Deref and DerefMut
 * Probably also need to wrap my head around Pin<T>
 * One thing I'm concerned about is the lifetime of references to the string
 * AKA, re-encryption when out of scope
 * Might need to hand out a separate "EncStringRef" type, which implements Drop
 *
 * Then have a combo of "string arbiter which decrypts on the fly", and reference thin object
 * which basically exists to encrypt at rest when the reference count is decremented
 * Mutations over the use of the reference should be fine since they'd all be proxied through Deref
 * So things like key rotation wouldn't be noticeable
 */

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
 * Plan for reordering
 * Probably can just be lazy and do a 2 pass thing
 * Grab the annotated statements, throw them in a list
 * Shuffle the list
 * Re-pass through the statement block
 * If a statement is annotated, replace it with the head of the shuffled list and pop the head off
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

/*
 * Also should probably get a nightly build up and running just so I can use cargo expand to verify
 * what I'm actually doing at this point
 */

/*
 * Shuffle is on hold pending a better solution
 * Currently, you can't actually add custom attributes to arbitrary statements
 * See the following example:
 *
 *   #[shuffle]
 *   fn shuffled() {
 *       #[shufflecase]
 *       println!("Shuffle line 1");
 *       println!("Shuffle line 2");
 *       println!("Shuffle line 3");
 *       #[shufflecase]
 *       println!("Shuffle line 4");
 *       println!("Shuffle line 5");
 *       #[shufflecase]
 *       println!("Shuffle line 6");
 *   }
 *
 * Trying to register a proc macro for shufflecase produces an error complaining that it's not
 * possible and to see a github issue for more information.
 * That leads down a rabbit hole of issues, stabilization, proc_macro hygiene and functionality
 * rewrites, a total mess.
 * But the end result is that no, it's not supported, not likely to be added any time soon, tough
 * luck.
 * Meaning, if we want to have this kind of functionality, another approach may be required.
 *
 * Few ideas:
 *  - Run this stuff at a build script level, automatically preprocess the entire file prior to
 *  compilation
 *  - Custom preprocessor (which honestly could still be Rust), that runs prior to compilation
 *  - Simple preprocessor that does string parsing style replacement
 *
 * Main question is how that preprocessor would work
 * Do we call it from a build script level?
 * Can build scripts actually modify code?
 * Can build scripts remove existing files from compilation? (Modify a copy, and ignore the
 * original)
 * Or do we have to hook it into cargo separately, like as an entire foreign application that runs
 * prior to "cargo build"?
 */

pub fn obfuscate(input: &String) -> String {
    let mut input2 = syn::parse_file(&input).unwrap();

    //eprintln!("INPUT: {:#?}", input2);
    //eprintln!("INFORMAT: {}", prettyplease::unparse(&input2));

    shuffle(&mut input2);
    encrypt_strings(&mut input2);

    //eprintln!("OUTPUT: {:#?}", input2);
    //eprintln!("OUTFORMAT: {}", prettyplease::unparse(&input2));

    prettyplease::unparse(&input2)
}

pub fn generate_temp_folder_name(name: Option<&str>) -> Utf8PathBuf {
    let mut output = Utf8PathBuf::from_path_buf(env::temp_dir()).unwrap();
    output.push(name.unwrap_or(".r2d2_build_dir"));
    output
}

pub fn obfuscate_dir(dir: &Utf8PathBuf) -> io::Result<()> {
    //WalkDir filter_entry will prevent the directory from being touched, so have to filter
    //manually
    for file in WalkDir::new(dir) {
        let file_path = file?.into_path();
        if file_path.to_str().unwrap_or_default().ends_with(".rs") {
            let contents = fs::read_to_string(&file_path)?;
            let obfuscated = obfuscate(&contents);
            fs::write(&file_path, &obfuscated)?;
        }
    }
    Ok(())
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
}

pub fn get_src_dir() -> SourceInformation {
    let metadata = MetadataCommand::new().exec().unwrap();
    SourceInformation {
        workspace_root: metadata.workspace_root,
        target_dir: metadata.target_directory,
    }
}
