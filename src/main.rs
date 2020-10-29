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
use std::io::Read;
use std::{env, fs};
use std::path::PathBuf;
use sqlx;
use sqlx::{Connection, SqliteConnection};
use futures::TryStreamExt;

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

async fn iter_directory(dir: PathBuf) {
    //env::set_current_dir(PathBuf::from(dir));
    let current_dir = dir;
    println!(
        "in {:?}:",
        current_dir
    );

    for entry in fs::read_dir(current_dir).expect("Read current dir fail") {
        let entry = entry.expect("Get entry fail");
        let path = entry.path();

        if path.is_dir() {
            iter_directory(entry.path());
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
        }
    }
}

#[tokio::main]
pub async fn main() -> Result<(), sqlx::Error> {
    let mut conn = sqlx::SqliteConnection::connect("sqlite::memory:").await?;
    sqlx::query("CREATE TABLE \"file_table\" (
        \"path\"	TEXT NOT NULL,
        \"hash\"	TEXT NOT NULL,
        PRIMARY KEY(\"hash\")
    );").execute(&mut conn).await?;
    iter_directory(env::current_dir().expect("Get current dir fail"));

    /*sqlx::query("INSERT INTO `file_table` VALUE (?, ?)")
        .bind(String::from(file_name.to_str().expect("")))
        .bind(hash.clone())
        .execute(conn)
        .await;*/
    conn.close().await?;
    Ok(())
}