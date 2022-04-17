use camino::Utf8PathBuf;
use lazy_static::lazy_static;
use r2d2::*;
use std::fs;
use std::fs::DirBuilder;
use std::io;
use std::io::Write;
use std::process::{Command, ExitStatus};
use std::sync::{Mutex, MutexGuard};

const TEST_DIRECTORY: &str = ".r2d2_test_dir";

lazy_static! {
    static ref FILESYSTEM_MUTEX: Mutex<()> = Mutex::new(());
}

//TODO: Figure out a nice way to handle output gathering without constantly modifying this file

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

fn compile_test(path: &str) -> ExitStatus {
    let _lock = lock_filesystem();

    let config = R2D2Config {
        dest_name: Some(TEST_DIRECTORY),
        cargo_args: None,
        need_run: false,
        need_obfuscate: true,
        obfuscate_dir: Some(path),
        stream_output: false,
    };

    build(&config).unwrap()
}

fn functional_test(path: &str) -> ExitStatus {
    let _lock = lock_filesystem();

    let config = R2D2Config {
        dest_name: Some(TEST_DIRECTORY),
        cargo_args: None,
        need_run: true,
        need_obfuscate: true,
        obfuscate_dir: Some(path),
        stream_output: false,
    };

    build(&config).unwrap()
}

mod single {
    use crate::*;

    #[test]
    fn hello_world_compile() {
        let status = compile_test("tests/single/01-hello_world");
        assert!(status.success());
    }

    #[test]
    fn hello_world_functional() {
        let status = functional_test("tests/single/01-hello_world");
        assert!(status.success());
    }

    #[test]
    fn prints_compile() {
        let status = compile_test("tests/single/02-prints");
        assert!(status.success());
    }

    #[test]
    fn prints_functional() {
        let status = functional_test("tests/single/02-prints");
        assert!(status.success());
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use crate::*;
        #[test]
        fn crazy_compile() {
            let status = compile_test("tests/single/03-crazy");
            assert!(status.success());
        }
    }

    #[test]
    fn shuffle_prints_compile() {
        let status = compile_test("tests/single/04-shuffle_prints");
        assert!(status.success());
    }

    #[test]
    fn shuffle_prints_functional() {
        let status = functional_test("tests/single/04-shuffle_prints");
        assert!(status.success());
    }

    #[test]
    fn shuffle_let_compile() {
        let status = compile_test("tests/single/05-shuffle_let");
        assert!(status.success());
    }

    #[test]
    fn shuffle_let_functional() {
        let status = functional_test("tests/single/05-shuffle_let");
        assert!(status.success());
    }

    #[test]
    fn shuffle_nested_compile() {
        let status = compile_test("tests/single/06-shuffle_nested");
        assert!(status.success());
    }

    #[test]
    fn shuffle_nested_functional() {
        let status = functional_test("tests/single/06-shuffle_nested");
        assert!(status.success());
    }

    #[test]
    fn assert_shatter_compile() {
        let status = compile_test("tests/single/07-assert_shatter");
        assert!(status.success());
    }

    #[test]
    fn assert_shatter_functional() {
        let status = functional_test("tests/single/07-assert_shatter");
        assert!(status.success());
    }
}

mod complex {
    use crate::*;

    #[test]
    fn rand_compile() {
        let status = compile_test("tests/complex/rand");
        assert!(status.success());
    }
}
