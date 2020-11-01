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
use std::fs::{File, rename};
use std::io::{Read, ErrorKind};
use std::{env, fs};
use std::path::PathBuf;
use rusqlite::{params, Connection};

#[derive(Debug)]
struct HashedFile {
    file_name: String,
    path: PathBuf,
    hash: String
}

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

fn iter_directory(dir: PathBuf) -> Vec<HashedFile> {

    let mut files = Vec::new();
    let current_dir = dir;
    println!("in {}:", current_dir.to_str().unwrap());

    for entry in fs::read_dir(current_dir).expect("Read current dir fail") {
        let entry = entry.expect("Get entry fail");
        let path = entry.path();
        let path_str = path.to_str().unwrap();

        if path.is_dir() {
            if path_str.ends_with(".git") || path_str.ends_with("target") || path_str.ends_with("samefile") {
                println!("Skipped path: {}", path.to_str().unwrap());
                continue;
            }
            files.extend(iter_directory(entry.path()));

            continue;
        }

        let file_name = path.file_name().ok_or("No filename")
            .expect("Get filename fail");
        let hash = match get_file_sha256(&path) {
            None => continue,
            Some(hash) => hash
        };
        println!("filename: {:?}, sha256: {:?}", file_name, hash.clone());
        files.push(HashedFile{
            file_name: String::from(path_str),
            path,
            hash
        });
    }
    files
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

fn main() {
    let conn = Connection::open_in_memory().expect("Create sqlite connection error");
    conn.execute("CREATE TABLE \"file_table\" (
        \"path\"	TEXT NOT NULL,
        \"hash\"	TEXT NOT NULL,
        PRIMARY KEY(\"hash\")
        );",
    params![]
    ).expect("Create table fail");

    let cwd = env::current_dir().unwrap();
    let current_cwd_len = cwd.to_str().unwrap().len();
    create_dir("samehash", None);
    println!("Current path: {}", cwd.to_str().unwrap());
    let files = iter_directory(cwd);

    for f in files {
        let mut stmt = conn.prepare("SELECT 1 FROM \"file_table\" WHERE \"hash\" = ?1")
            .expect("Prepare statement fail");
        let result = stmt.query_row(params![f.hash], |_row| Ok(()));
        match result {
            Ok(_) => {
                let target = String::from(f.path.clone().to_str().unwrap())
                    .split_at(current_cwd_len + 1)
                    .1
                    .replace("\\", ".")
                    .replace("/", ".");
                let prefix = PathBuf::from("samehash/");
                let rename_target = prefix.join(f.hash.clone()).join(target.clone());
                println!("Find duplicate file: {}, move to: {:?}", f.file_name, rename_target.clone());
                create_dir(f.hash.clone().as_str(), Option::from("samehash"));
                let _result = rename(f.path, rename_target).unwrap();
            },
            Err(e) => match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    conn.execute(
                        "INSERT INTO \"file_table\" VALUES (?1, ?2)",
                        params![f.file_name, f.hash])
                        .expect("Insert data fail");
                }
                _ => eprintln!("Query problem: {:?}", e)
            }
        }
    }
    conn.close().expect("Close connection error");
}