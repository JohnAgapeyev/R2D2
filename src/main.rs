use camino::Utf8Path;
use camino::Utf8PathBuf;
use cargo_metadata::MetadataCommand;
use r2d2::obfuscate;
use std::env;
use std::fs;
use std::fs::DirBuilder;
use std::fs::OpenOptions;
use std::io;
use std::io::ErrorKind;
use std::process::Command;
use std::process::Stdio;
use walkdir::WalkDir;

fn generate_temp_folder_name() -> Utf8PathBuf {
    let mut output = Utf8PathBuf::from_path_buf(env::temp_dir()).unwrap();
    output.push(".r2d2_build_dir");
    output
}

//TODO: Only copy differences with hashes/mtime checks
//TODO: This needs to be optimized and cleaned up
//TODO: Fix the error checking
fn copy_dir(from: &Utf8PathBuf, to: &Utf8PathBuf) -> io::Result<()> {
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

        if file.ends_with(".rs") {
            let contents = fs::read_to_string(src_file)?;
            let obfuscated = obfuscate(&contents);
            fs::write(dest_file, &obfuscated)?;
        } else {
            fs::copy(src_file, dest_file)?;
        }
    }

    Ok(())
}

struct SourceInformation {
    workspace_root: Utf8PathBuf,
    target_dir: Utf8PathBuf,
}

fn get_src_dir() -> SourceInformation {
    let metadata = MetadataCommand::new().exec().unwrap();
    println!("Root is at {}", metadata.workspace_root);
    SourceInformation {
        workspace_root: metadata.workspace_root,
        target_dir: metadata.target_directory,
    }
}

fn main() -> io::Result<()> {
    let src = get_src_dir();
    let dest = generate_temp_folder_name();

    if let Ok(_) = std::fs::metadata(&dest) {
        //Clean up the folder if it already exists
        let _ = fs::remove_dir_all(&dest);
    }

    DirBuilder::new().recursive(true).create(&dest)?;

    copy_dir(&src.workspace_root, &dest)?;

    println!("Calling cargo build");

    Command::new("cargo")
        .arg("build")
        .arg("--target-dir")
        .arg(&src.target_dir)
        .current_dir(&dest)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .expect("failed to execute process");

    println!("Process is done");

    //Don't remove the build dir, we want to debug it if things go wrong

    Ok(())
}
