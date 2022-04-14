use camino::Utf8PathBuf;
use lazy_static::lazy_static;
use r2d2::*;
use std::fs;
use std::fs::DirBuilder;
use std::io;
use std::io::Write;
use std::process::Command;
use std::process::Output;
use std::sync::{Mutex, MutexGuard};

const TEST_DIRECTORY: &str = ".r2d2_test_dir";

lazy_static! {
    static ref FILESYSTEM_MUTEX: Mutex<()> = Mutex::new(());
}

//TODO: Figure out a nice way to handle output gathering without constantly modifying this file
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

fn lock_filesystem() -> MutexGuard<'static, ()> {
    /*
     * Ignore filesystem mutex poisoning
     * The failures will be due to crashes in tests, and we test from a clean slate anyhow
     * Don't need to have extraneous test failures
     */
    match FILESYSTEM_MUTEX.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn compile_test(path: &str) -> Output {
    let _lock = lock_filesystem();
    let (src, dest) = setup_test_crate(path).unwrap();

    Command::new("cargo")
        .arg("build")
        .arg("--target-dir")
        .arg(&src)
        .current_dir(&dest)
        .output()
        .unwrap()
}

fn functional_test(path: &str) -> Output {
    let _lock = lock_filesystem();
    let (src, dest) = setup_test_crate(path).unwrap();

    Command::new("cargo")
        .arg("run")
        .arg("--target-dir")
        .arg(&src)
        .current_dir(&dest)
        .output()
        .unwrap()
}

mod single {
    use crate::*;

    #[test]
    fn hello_world_compile() {
        let output = compile_test("tests/single/01-hello_world");

        io::stdout().write_all(&output.stdout).unwrap();
        io::stderr().write_all(&output.stderr).unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn hello_world_functional() {
        let output = functional_test("tests/single/01-hello_world");
        assert!(output.status.success());
    }

    #[test]
    fn prints_compile() {
        let output = compile_test("tests/single/02-prints");
        assert!(output.status.success());
    }

    #[test]
    fn prints_functional() {
        let output = functional_test("tests/single/02-prints");
        assert!(output.status.success());
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use crate::*;
        #[test]
        fn crazy_compile() {
            let output = compile_test("tests/single/03-crazy");
            io::stdout().write_all(&output.stdout).unwrap();
            io::stderr().write_all(&output.stderr).unwrap();
            assert!(output.status.success());
        }
    }

    #[test]
    fn shuffle_prints_compile() {
        let output = compile_test("tests/single/04-shuffle_prints");
        assert!(output.status.success());
    }

    #[test]
    fn shuffle_prints_functional() {
        let output = functional_test("tests/single/04-shuffle_prints");
        assert!(output.status.success());
    }

    #[test]
    fn shuffle_let_compile() {
        let output = compile_test("tests/single/05-shuffle_let");
        assert!(output.status.success());
    }

    #[test]
    fn shuffle_let_functional() {
        let output = functional_test("tests/single/05-shuffle_let");
        assert!(output.status.success());
    }

    #[test]
    fn shuffle_nested_compile() {
        let output = compile_test("tests/single/06-shuffle_nested");
        assert!(output.status.success());
    }

    #[test]
    fn shuffle_nested_functional() {
        let output = functional_test("tests/single/06-shuffle_nested");
        assert!(output.status.success());

        io::stdout().write_all(&output.stdout).unwrap();
        io::stderr().write_all(&output.stderr).unwrap();
    }

    #[test]
    fn assert_shatter_compile() {
        let output = compile_test("tests/single/07-assert_shatter");

        io::stdout().write_all(&output.stdout).unwrap();
        io::stderr().write_all(&output.stderr).unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn assert_shatter_functional() {
        let output = functional_test("tests/single/07-assert_shatter");

        io::stdout().write_all(&output.stdout).unwrap();
        io::stderr().write_all(&output.stderr).unwrap();
        assert!(output.status.success());
    }
}

mod complex {
    use crate::*;

    #[test]
    fn rand_compile() {
        let output = compile_test("tests/complex/rand");

        io::stdout().write_all(&output.stdout).unwrap();
        io::stderr().write_all(&output.stderr).unwrap();
        assert!(output.status.success());
    }
}
