/*
 ** Copyright (C) 2020 KunoiSayami
 **
 ** This file is part of File-duplicate-checker and is released under
 ** the AGPL v3 License: https://www.gnu.org/licenses/agpl-3.0.txt
 **
 ** This program is free software: you can redistribute it and/or modify
 ** it under the terms of the GNU Affero General Public License as published by
 ** the Free Software Foundation, either version 3 of the License, or
 ** any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 ** GNU Affero General Public License for more details.
 **
 ** You should have received a copy of the GNU Affero General Public License
 ** along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{Read, ErrorKind, Write};
use std::{env, fs};
use std::path::PathBuf;
use sqlx::{Connection, SqliteConnection};
use anyhow::Result;

fn get_file_sha256(s: &PathBuf) -> Option<String> {
    let mut file = match File::open(&s) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("Open {:?} error {:?}", s, error);
            return None
        }
    };
    let mut sha256 = Sha256::new();
    let mut buffer = [0; 1024];
    loop {
        let size = file.read(&mut buffer).expect("Fail");
        sha256.update(&buffer[..size]);
        if size < 1024 {
            break
        }
    }
    let result = sha256.finalize();
    Option::from(format!("{:x}", result))
}

fn iter_directory(dir: &PathBuf) -> Result<(Vec<PathBuf>, u32)> {
    println!("in {}:", dir.to_str().unwrap());
    let mut files = 0u32;
    let mut dirs = vec![dir.clone()];
    let current_idr = dir;
    for entry in fs::read_dir(current_idr)? {
        let entry = entry?;
        let path = entry.path();
        let path_str = path.to_str().unwrap();
        if path.is_dir() {
            if path_str.ends_with(".git") || path_str.ends_with("target") || path_str.ends_with("samehash") {
                println!("Skipped path: {}", path.to_str().unwrap());
                continue;
            }
            //dirs.push(path.clone());
            let r = iter_directory(&path)?;
            dirs.extend(r.0);
            files += r.1;
        }
        else {
            files += 1;
        }
    }
    Ok((dirs, files))
}

async fn iter_files(current_dir: PathBuf, path_db: Option<&str>) -> Result<u64> {

    let mut num = 0u64;
    if path_db.is_some() {
        let file = std::path::Path::new(path_db.clone().unwrap());
        if !file.exists() {
            std::fs::File::create(file)?;
        }
    }
    let mut conn = SqliteConnection::connect(path_db.unwrap_or("sqlite::memory:")).await?;
    if sqlx::query(r#"SELECT name FROM sqlite_master WHERE type='table' AND "name"='file_table' "#)
        .fetch_all(&mut conn)
        .await?.is_empty() {
        sqlx::query("CREATE TABLE \"file_table\" (
                \"path\"	TEXT NOT NULL,
                \"hash\"	TEXT NOT NULL,
                PRIMARY KEY(\"hash\")
                );").execute(&mut conn)
            .await?;
    }
    let current_dir_len = current_dir.to_str().unwrap().len();

    let (directories, approximately_file_num) = iter_directory(&current_dir)?;
    let mut current_progress = 0u32;
    println!();
    for dir in directories {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            let path_str = path.to_str().unwrap();
            if path.is_dir() {
                continue;
            }

            let file_name = path.file_name().ok_or("No filename")
                .expect("Get filename fail");

            if vec![".py", ".db", ".json"].into_iter().any(|x| path_str.ends_with(x)) {
                continue
            }
            current_progress += 1;
            print!("\r({}/{}), name: {:<20?}", current_progress, approximately_file_num, file_name);
            std::io::stdout().flush()?;
            let hash = match get_file_sha256(&path) {
                None => continue,
                Some(hash) => hash
            };
            let file_name = file_name.to_str().unwrap().to_string();
            let dup = {
                let r = sqlx::query(r#"SELECT 1 FROM "file_table" WHERE "hash" = ?"#)
                    .bind(hash.clone())
                    .fetch_all(&mut conn)
                    .await?;
                if r.is_empty() {
                    sqlx::query("INSERT INTO \"file_table\" VALUES (?, ?)")
                        .bind(file_name.clone())
                        .bind( hash.clone())
                        .execute(&mut conn)
                        .await?;
                }
                !r.is_empty()
            };

            if dup {
                let target = String::from(path.clone().to_str().unwrap())
                    .split_at(current_dir_len)
                    .1
                    .replace("\\", ".")
                    .replace("/", ".");
                let prefix = PathBuf::from("samehash/");
                let rename_target = prefix.join(hash.clone()).join(target.clone());
                println!("\rFind duplicate file: {}, move to: {:?}", file_name, rename_target.clone());
                create_dir(hash.clone().as_str(), Option::from("samehash"));
                fs::rename(path, rename_target).unwrap();
                num += 1;
            }
        }
    }
    Ok(num)
}

fn create_dir(p: &str, d: Option<&str>) {
    let path = PathBuf::from(d.unwrap_or(".")).join(p);
    match fs::create_dir(path) {
        Ok(_) => {}
        Err(e) => match e.kind() {
            ErrorKind::AlreadyExists => {}
            _ => panic!("Fatal error: {:?}", e)
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use std::path::Path;
    use std::fs::OpenOptions;
    use std::io::Write;

    fn write_file(file_name: &str, bytes: usize) -> Result<()> {
        let s = std::iter::repeat("\0").take(bytes).collect::<String>();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(Path::join(Path::new("."), file_name))?;
        file.write(s.as_bytes())?;
        Ok(())
    }

    #[test]
    fn test() {
        let test_dir = Path::new("test");
        if test_dir.exists() {
            fs::remove_dir_all(test_dir).unwrap();
        }

        fs::create_dir(test_dir).unwrap();
        std::env::set_current_dir(test_dir).unwrap();
        fs::create_dir(Path::new("samehash")).unwrap();
        write_file("1.txt", 5).unwrap();
        write_file("2.txt", 5).unwrap();
        write_file("3.txt", 5).unwrap();
        write_file("4.txt", 5).unwrap();
        write_file("5.txt", 6).unwrap();
        write_file("114514.txt", 2048).unwrap();
        write_file("9.txt", 2048).unwrap();
        let current_env = env::current_dir().unwrap();
        let r = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(iter_files(current_env, None))
            .unwrap();
        assert_eq!(r, 4);
    }
}


#[tokio::main]
async fn main() ->Result<()> {

    let cwd = env::current_dir().unwrap();
    create_dir("samehash", None);
    println!("Current path: {}", cwd.to_str().unwrap());
    iter_files(cwd, {
        if std::env::args().into_iter().any(|x| x.eq("--memory")) {
            None
        } else {
            Some("samehash.db")
        }
    }).await?;

    Ok(())
}