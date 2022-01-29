use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use std::fs;
use std::fs::DirBuilder;
use std::fs::OpenOptions;
use std::io;
use std::io::ErrorKind;
use std::path::PathBuf;
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

//fn get_dir_tree(entry: DirEntry) -> Vec<DirEntry> {
//    match entry.file_type() {
//        Err(_) => return Vec::new(),
//        Ok(t) if !t.is_dir() => return Vec::new(),
//        _ => {}
//    }
//
//    let (dirs, files): (Vec<DirEntry>, Vec<DirEntry>) = fs::read_dir(env::current_dir()?)?
//        .filter_map(|entry| entry.ok())
//        .filter(|entry| entry.file_type().is_ok())
//        .filter(|entry| {
//            entry
//                .file_name()
//                .into_string()
//                .unwrap_or(String::new())
//                .chars()
//                .nth(0)
//                .unwrap_or('a')
//                != '.'
//        })
//    .partition(|entry| entry.file_type().unwrap().is_dir());
//
//    files.append(get_dir_tree);
//}

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

    dirs.into_iter().for_each(|d| {
        let mut dest_dir = String::from(to.to_str().unwrap());
        dest_dir.push_str(
            d.path()
                .to_str()
                .unwrap()
                .strip_prefix(from.to_str().unwrap())
                .unwrap(),
        );

        println!("{:#?}\n{:#?}", d.path(), &dest_dir);

        //TODO: This is all a mess
        DirBuilder::new().recursive(true).create(&dest_dir).unwrap();
    });

    files
        .into_iter()
        .for_each(|f| {
            let mut dest_file = String::from(to.to_str().unwrap());
            dest_file.push_str(
                f.path()
                    .to_str()
                    .unwrap()
                    .strip_prefix(from.to_str().unwrap())
                    .unwrap(),
            );

            println!("{:#?}\n{:#?}", f.path(), &dest_file);
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&dest_file).unwrap();
            fs::copy(f.path(), dest_file);
        });

    Ok(())
}

fn main() -> io::Result<()> {
    println!("Hello world");

    let src = env::current_dir()?;
    let dest = generate_temp_folder_name();

    DirBuilder::new().recursive(true).create(&dest)?;

    copy_dir(&src, &dest)?;

    fs::remove_dir_all(dest)?;

    Ok(())
}
