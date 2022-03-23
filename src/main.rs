use clap::{app_from_crate, arg, App, AppSettings};
use r2d2::*;
use std::env;
use std::fs;
use std::fs::DirBuilder;
use std::io;
use std::process::Command;
use std::process::Stdio;

fn main() -> io::Result<()> {
    let matches = app_from_crate!()
        .global_setting(AppSettings::PropagateVersion)
        .global_setting(AppSettings::UseLongFormatForHelpSubcommand)
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            App::new("build")
                .about("Compile a local package and all of its dependencies")
                .arg(
                    arg!(args: [args])
                        .help("Arguments to pass to cargo")
                        .multiple_occurrences(true)
                        .last(true)
                        .required(false),
                ),
        )
        .subcommand(
            App::new("check")
                .about(
                    "Analyze the current package and report errors, but don't build object files",
                )
                .arg(
                    arg!(args: [args])
                        .help("Arguments to pass to cargo")
                        .multiple_occurrences(true)
                        .last(true)
                        .required(false),
                ),
        )
        .subcommand(
            App::new("clean")
                .about("Remove artifacts that cargo has generated in the past")
                .arg(
                    arg!(args: [args])
                        .help("Arguments to pass to cargo")
                        .multiple_occurrences(true)
                        .last(true)
                        .required(false),
                ),
        )
        .subcommand(
            App::new("run")
                .about("Run a binary or example of the local package")
                .arg(
                    arg!(args: [args])
                        .help("Arguments to pass to cargo")
                        .multiple_occurrences(true)
                        .last(true)
                        .required(false),
                ),
        )
        .subcommand(
            App::new("test")
                .about(
                    "Execute all unit and integration tests and build examples of a local package",
                )
                .arg(
                    arg!(args: [args])
                        .help("Arguments to pass to cargo")
                        .multiple_occurrences(true)
                        .last(true)
                        .required(false),
                ),
        )
        .arg(arg!(-p --plain "Disable obfuscation of the workspace").required(false))
        .get_matches();

    let cargo_args: Vec<&str>;

    match matches.subcommand() {
        Some(("build", sub_matches)) => {
            cargo_args = sub_matches
                .values_of("args")
                .map(|vals| vals.collect::<Vec<_>>())
                .unwrap_or_default();
            println!("Build was called with args {:#?}", &cargo_args)
        }
        Some(("check", sub_matches)) => {
            cargo_args = sub_matches
                .values_of("args")
                .map(|vals| vals.collect::<Vec<_>>())
                .unwrap_or_default();
            println!("Check was called with args {:#?}", &cargo_args)
        }
        Some(("clean", sub_matches)) => {
            cargo_args = sub_matches
                .values_of("args")
                .map(|vals| vals.collect::<Vec<_>>())
                .unwrap_or_default();
            println!("Clean was called with args {:#?}", &cargo_args)
        }
        Some(("run", sub_matches)) => {
            cargo_args = sub_matches
                .values_of("args")
                .map(|vals| vals.collect::<Vec<_>>())
                .unwrap_or_default();
            println!("Run was called with args {:#?}", &cargo_args)
        }
        Some(("test", sub_matches)) => {
            cargo_args = sub_matches
                .values_of("args")
                .map(|vals| vals.collect::<Vec<_>>())
                .unwrap_or_default();
            println!("Test was called with args {:#?}", &cargo_args)
        }
        _ => unreachable!(
            "Exhausted list of subcommands and SubcommandRequiredElseHelp prevents `None`"
        ),
    }

    //Unwrap can't fail due to previous match unreachable check
    let cargo_subcommand = matches.subcommand_name().unwrap();

    let no_obfuscate = matches.is_present("plain");
    println!("Are we obfuscating? {}", !&no_obfuscate);

    let src = get_src_dir();
    let dest = generate_temp_folder_name(None);

    if let Ok(_) = std::fs::metadata(&dest) {
        //Clean up the folder if it already exists
        let _ = fs::remove_dir_all(&dest);
    }

    DirBuilder::new().recursive(true).create(&dest)?;

    copy_dir(&src.workspace_root, &dest, no_obfuscate)?;

    println!("Calling cargo");

    Command::new("cargo")
        .arg(cargo_subcommand)
        .arg("--target-dir")
        .arg(&src.target_dir)
        .args(cargo_args)
        .current_dir(&dest)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .expect("failed to execute process");

    println!("Process is done");

    //Don't remove the build dir, we want to debug it if things go wrong

    Ok(())
}
