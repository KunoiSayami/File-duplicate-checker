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
#![feature(async_closure)]
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Read;
use std::{env, fs};
use std::path::PathBuf;
use rusqlite::{params, Connection, Result};

#[derive(Debug)]
struct HashedFile {
    file_name: String,
    hash: String
}

fn get_file_sha256(s: &PathBuf) -> String {
    let mut file = File::open(&s).expect(&*format!("Open {:?} fail", &s));
    let mut sha256 = Sha256::new();
    let mut buffer = [0; 1024];
    loop {
        let size = file.read(&mut buffer).expect("Fail");
        sha256.update(&buffer[..size]);
        //println!("{}", size);
        if size < 1024 {
            break
        }
    }
    let result = sha256.finalize();
    format!("{:x}", result)
}

fn iter_directory(dir: PathBuf) -> Vec<HashedFile> {
    //env::set_current_dir(PathBuf::from(dir));
    let mut files = Vec::new();
    let current_dir = dir;
    println!(
        "in {:?}:",
        current_dir
    );

    for entry in fs::read_dir(current_dir).expect("Read current dir fail") {
        let entry = entry.expect("Get entry fail");
        let path = entry.path();
        let path_str = path.to_str().expect("");

        if path.is_dir() {
            if path_str.ends_with(".git") || path_str.ends_with("target") {
                continue;
            }
            files.extend(iter_directory(entry.path()));

            continue;
        }
        let metadata = fs::metadata(&path).expect("Get metadata fail");

        let file_name = path.file_name().ok_or("No filename")
            .expect("Get filename fail");
        let hash = get_file_sha256(&path);

        if metadata.is_file() {
            println!(
                "filename: {:?}, sha256: {:?}",
                file_name,
                hash.clone()
            );
            files.push(HashedFile{file_name: String::from(path_str), hash });
        }
    }
    files
}

fn main() {
    let conn = Connection::open_in_memory().expect("Create sqlite connection error");
    //let mut conn = sqlx::SqliteConnection::connect("sqlite::memory:").await?;
    conn.execute("CREATE TABLE \"file_table\" (
        \"path\"	TEXT NOT NULL,
        \"hash\"	TEXT NOT NULL,
        PRIMARY KEY(\"hash\")
        );",
    params![]
    ).expect("Create table fail");
    let files = iter_directory(env::current_dir().expect("Get current dir fail"));
    println!("{}", files.len());
    files.iter().map(|x|{
        conn.execute("INSERT INTO \"file_table\" VALUE (?1, ?2)", params![x.file_name, x.hash]).expect("Insert data fail");
    });
    conn.close().expect("Close connection error");
}