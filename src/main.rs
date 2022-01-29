use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use std::fs;
use std::fs::DirBuilder;
use std::fs::OpenOptions;
use std::io;
use std::io::ErrorKind;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use walkdir::DirEntry;
use walkdir::WalkDir;

fn generate_temp_folder_name() -> PathBuf {
    let mut output = env::temp_dir();
    output.push(format!(
        ".r2d2_build_dir_{}{}{}{}",
        OsRng.next_u64(),
        OsRng.next_u64(),
        OsRng.next_u64(),
        OsRng.next_u64()
    ));
    output
}

fn copy_dir(from: &PathBuf, to: &PathBuf) -> io::Result<()> {
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

    let (dirs, files): (Vec<DirEntry>, Vec<DirEntry>) = files
        .into_iter()
        .map(|f| f.unwrap())
        .partition(|e| e.file_type().is_dir());

    dirs.into_iter()
        .map(|d| {
            String::from(
                d.path()
                    .to_str()
                    .unwrap()
                    .strip_prefix(from.to_str().unwrap())
                    .unwrap(),
            )
        })
        .filter(|filename| !filename.contains("/target"))
        .for_each(|filename| {
            let mut dest_dir = String::from(to.to_str().unwrap());

            dest_dir.push_str(&filename);

            //TODO: This is all a mess
            DirBuilder::new().recursive(true).create(&dest_dir).unwrap();
        });

    files
        .into_iter()
        .map(|f| {
            String::from(
                f.path()
                    .to_str()
                    .unwrap()
                    .strip_prefix(from.to_str().unwrap())
                    .unwrap(),
            )
        })
        .filter(|filename| !filename.contains("/target"))
        .for_each(|filename| {
            let mut dest_file = String::from(to.to_str().unwrap());
            dest_file.push_str(&filename);

            let mut src_file = String::from(from.to_str().unwrap());
            src_file.push_str(&filename);

            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&dest_file)
                .unwrap();
            fs::copy(Path::new(&src_file), dest_file).unwrap();
        });

    Ok(())
}

fn main() -> io::Result<()> {
    println!("Hello world");

    let src = env::current_dir()?;
    let dest = generate_temp_folder_name();

    DirBuilder::new().recursive(true).create(&dest)?;

    copy_dir(&src, &dest)?;

    let output = Command::new("cargo")
        .arg("build")
        .arg("--target-dir")
        .arg(format!("{}/target", src.to_str().unwrap()))
        .current_dir(&dest)
        .output()
        .expect("failed to execute process");

    io::stdout().write_all(&output.stdout).unwrap();
    io::stderr().write_all(&output.stderr).unwrap();

    fs::remove_dir_all(dest)?;

    Ok(())
}
