use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use std::fs;
use std::fs::DirEntry;
use std::io;
use std::path::PathBuf;
use walkdir::WalkDir;

fn create_working_dir() -> PathBuf {
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

fn copy_dir() -> io::Result<()> {
    let dest = create_working_dir();

    //let (dirs, files): (Vec<DirEntry>, Vec<DirEntry>) = fs::read_dir(env::current_dir()?)?
    //    .filter_map(|entry| entry.ok())
    //    .filter(|entry| entry.file_type().is_ok())
    //    .filter(|entry| {
    //        entry
    //            .file_name()
    //            .into_string()
    //            .unwrap_or(String::new())
    //            .chars()
    //            .nth(0)
    //            .unwrap_or('a')
    //            != '.'
    //    })
    //    .partition(|entry| entry.file_type().unwrap().is_dir());

    //let df: Vec<DirEntry> = dirs
    //    .iter()
    //    .flat_map(|dir| fs::read_dir(dir.path()))
    //    .filter_map(|entry| entry.ok())
    //    //.map(|entry| entry.ok())
    //    //.collect::<Vec<_>>();
    //    .collect();
    let files: Vec<_> = WalkDir::new(env::current_dir()?)
        .into_iter()
        .filter_entry(|e| {
            !e.file_name()
                .to_str()
                .map(|s| s.starts_with("."))
                .unwrap_or(false)
        })
        .filter(|e| e.is_ok())
        .map(|e| e.unwrap())
        .collect();

    files.iter().map(|file| file.path()).for_each(|file| fs::copy());

    //println!("{:#?}", dirs);
    println!("{:#?}", files);
    //println!("{:#?}", df);
    Ok(())
}

fn main() -> io::Result<()> {
    println!("Hello world");
    println!("Creating {:#?}", create_working_dir().as_os_str());

    copy_dir()?;

    Ok(())
}
