use camino::Utf8PathBuf;
use r2d2::*;
use std::fs;
use std::fs::DirBuilder;
use std::io;
use std::process::Command;
use std::process::Stdio;

#[test]
fn main() -> io::Result<()> {
    /*
     * Don't need to override src dir due to dependency resolution
     * We rely on r2d2 crate for all the test crates
     * So we need to copy from the workspace root so that the parent directory lookup succeeds
     * Setting the cargo current_dir for building is adequate to avoid out-of-scope builds/tests
     */
    let src = get_src_dir();
    let dest = generate_temp_folder_name(Some(".r2d2_test_dir"));

    if let Ok(_) = std::fs::metadata(&dest) {
        //Clean up the folder if it already exists
        let _ = fs::remove_dir_all(&dest);
    }

    DirBuilder::new().recursive(true).create(&dest)?;

    //TODO: Make this nice with concat! instead of full path prints
    //let true_dest = Utf8PathBuf::from("/tmp/.r2d2_test_dir/tests/single/01-hello_world");
    let true_dest = Utf8PathBuf::from("/tmp/.r2d2_test_dir/tests/single/02-prints");

    copy_dir(&src.workspace_root, &dest)?;
    obfuscate_dir(&true_dest)?;

    println!("Calling cargo");

    Command::new("cargo")
        .arg("build")
        .arg("--target-dir")
        .arg(&src.target_dir)
        .current_dir(&true_dest)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .expect("failed to execute process");

    println!("Process is done");

    Ok(())
}
