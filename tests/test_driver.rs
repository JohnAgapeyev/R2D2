use camino::Utf8PathBuf;
use lazy_static::lazy_static;
use r2d2::*;
use std::fs;
use std::fs::DirBuilder;
use std::io;
use std::process::Command;
use std::process::Stdio;
use std::sync::Mutex;

const TEST_DIRECTORY: &str = ".r2d2_test_dir";

lazy_static! {
    static ref FILESYSTEM_MUTEX: Mutex<()> = Mutex::new(());
}

fn setup_test_crate(path: &str) -> io::Result<(Utf8PathBuf, Utf8PathBuf)> {
    /*
     * Don't need to override src dir due to dependency resolution
     * We rely on r2d2 crate for all the test crates
     * So we need to copy from the workspace root so that the parent directory lookup succeeds
     * Setting the cargo current_dir for building is adequate to avoid out-of-scope builds/tests
     */
    let src = get_src_dir();
    let dest = generate_temp_folder_name(Some(TEST_DIRECTORY));

    if let Ok(_) = std::fs::metadata(&dest) {
        //Clean up the folder if it already exists
        let _ = fs::remove_dir_all(&dest);
    }

    DirBuilder::new().recursive(true).create(&dest)?;

    let mut true_dest_str = String::from(dest.as_str());
    true_dest_str.push('/');
    true_dest_str.push_str(path);

    let true_dest = Utf8PathBuf::from(true_dest_str);

    copy_dir(&src.workspace_root, &dest)?;
    obfuscate_dir(&true_dest)?;

    Ok((src.target_dir, true_dest))
}

mod simple {
    use crate::*;

    #[test]
    fn hello_world() {
        let _lock = FILESYSTEM_MUTEX.lock().unwrap();
        let (src, dest) = setup_test_crate("tests/single/01-hello_world").unwrap();

        println!("Calling cargo");

        Command::new("cargo")
            .arg("build")
            .arg("--target-dir")
            .arg(&src)
            .current_dir(&dest)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .expect("failed to execute process");

        println!("Process is done");

        Command::new("cargo")
            .arg("run")
            .arg("--target-dir")
            .arg(&src)
            .current_dir(&dest)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .expect("failed to execute process");

        println!("Execution is done");
    }

    #[test]
    fn prints() {
        let _lock = FILESYSTEM_MUTEX.lock().unwrap();
        let (src, dest) = setup_test_crate("tests/single/02-prints").unwrap();

        println!("Calling cargo");

        Command::new("cargo")
            .arg("build")
            .arg("--target-dir")
            .arg(&src)
            .current_dir(&dest)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .expect("failed to execute process");

        println!("Process is done");

        Command::new("cargo")
            .arg("run")
            .arg("--target-dir")
            .arg(&src)
            .current_dir(&dest)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .expect("failed to execute process");

        println!("Execution is done");
    }
}
