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
use std::io::{Read, ErrorKind};
use std::{env, fs};
use std::path::PathBuf;
use tokio::sync::Mutex;
use std::sync::Arc;
use sqlx::{Connection, SqliteConnection};
use anyhow::Result;

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


async fn iter_directory(dir: PathBuf, conn: Arc<Mutex<SqliteConnection>>, current_cwd_len: usize) -> Result<()> {

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
            iter_directory(entry.path(), Arc::clone(&conn), current_cwd_len).await?;

            continue;
        }

        let file_name = path.file_name().ok_or("No filename")
            .expect("Get filename fail");
        let hash = match get_file_sha256(&path) {
            None => continue,
            Some(hash) => hash
        };
        println!("filename: {:?}, sha256: {:?}", file_name, &hash);
        let file_name = file_name.to_str().unwrap().to_string();
        let dup = {
            let mut conn = conn.lock().await;
            let r = sqlx::query("SELECT 1 FROM 'file_table' WHERE 'hash' = ?")
                .bind(hash.clone())
                .fetch_all(&mut (*conn))
                .await?;
            if r.is_empty() {
                sqlx::query("INSERT INTO \"file_table\" VALUES (?, ?)")
                    .bind(file_name.clone())
                    .bind( hash.clone())
                    .execute(&mut (*conn))
                    .await?;
            }
            r.is_empty()
        };
        if dup {
            let target = String::from(path.clone().to_str().unwrap())
                .split_at(current_cwd_len + 1)
                .1
                .replace("\\", ".")
                .replace("/", ".");
            let prefix = PathBuf::from("samehash/");
            let rename_target = prefix.join(hash.clone()).join(target.clone());
            println!("Find duplicate file: {}, move to: {:?}", file_name, rename_target.clone());
            create_dir(hash.clone().as_str(), Option::from("samehash"));
            fs::rename(path, rename_target).unwrap();
        }
    }
    Ok(())
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

#[tokio::main]
async fn main() ->Result<()> {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await?;
    sqlx::query("CREATE TABLE \"file_table\" (
        \"path\"	TEXT NOT NULL,
        \"hash\"	TEXT NOT NULL,
        PRIMARY KEY(\"hash\")
        );").execute(&mut conn)
        .await?;

    let cwd = env::current_dir().unwrap();
    let current_cwd_len = cwd.to_str().unwrap().len();
    create_dir("samehash", None);
    println!("Current path: {}", cwd.to_str().unwrap());
    let arc = Arc::new(Mutex::new(conn));
    let files = iter_directory(cwd, arc.clone(), current_cwd_len).await?;

    drop(arc);
    Ok(())
}