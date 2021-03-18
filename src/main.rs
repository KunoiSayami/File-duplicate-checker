/*
 ** Copyright (C) 2020-2021 KunoiSayami
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
mod database;

use anyhow::Result;
use sha2::digest::DynDigest;
use sha2::{Digest, Sha256};
use sqlx::{Connection, SqliteConnection};
use std::io::{stdin, stdout, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{env, fs};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, BufReader};

const BUFFER_SIZE: usize = 1024 * 16;
const MAX_SIZE_LIMIT: usize = usize::MAX;
const DEFAULT_DATABASE_FILE: &str = "samehash.db";
const PEEK_SIZE: usize = BUFFER_SIZE * 8;

// https://www.reddit.com/r/rust/comments/8tfyof/noob_question_pause/
fn pause() {
    let mut stdout = stdout();
    stdout.write_all(b"Press Enter to continue...").unwrap();
    stdout.flush().unwrap();
    std::io::Read::read(&mut stdin(), &mut [0]).unwrap();
}

async fn get_file_sha256(s: &Path, read_size: usize) -> Option<String> {
    let file = match File::open(&s).await {
        Ok(file) => file,
        Err(error) => {
            eprintln!("Open {} error {:?}", String::from(s.to_str()?), error);
            return None;
        }
    };
    let mut file = BufReader::new(file);
    let mut sha256 = Sha256::new();
    let mut buffer = [0; BUFFER_SIZE];
    let mut rsize = 0usize;
    loop {
        let size = file.read(&mut buffer).await.ok()?;
        DynDigest::update(&mut sha256, &buffer[0..size]);
        rsize += size;
        if size < BUFFER_SIZE || rsize > read_size {
            break;
        }
    }
    let result = sha256.finalize();
    Option::from(format!("{:x}", result))
}

fn iter_directory(dir: &Path) -> Result<(Vec<PathBuf>, u32)> {
    let mut files = 0u32;
    let mut dirs = vec![dir.to_path_buf()];
    let current_idr = dir;
    let mut skipped: Vec<String> = Default::default();
    for entry in fs::read_dir(current_idr)? {
        let entry = entry?;
        let path = entry.path();
        let path_str = path.to_str().unwrap();
        if path.is_dir() {
            if vec![".git", "target", "samehash"]
                .into_iter()
                .any(|x| path_str.ends_with(x))
            {
                skipped.push(path.to_str().unwrap_or("").to_string());
                continue;
            }
            //dirs.push(path.clone());
            let r = iter_directory(&path)?;
            dirs.extend(r.0);
            files += r.1;
        } else {
            files += 1;
        }
    }
    println!("in {}: ({})", dir.to_str().unwrap_or(""), files);
    for x in skipped {
        println!("Skipped path: {}", x);
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
    if sqlx::query(r#"SELECT name FROM sqlite_master WHERE type='table' AND "name"='files'"#)
        .fetch_all(&mut conn)
        .await?
        .is_empty()
    {
        sqlx::query(
            r#"CREATE TABLE "files" (
                "path"	TEXT NOT NULL,
                "size"	INTEGER NOT NULL,
                "hhash"	TEXT,
                "hash"	TEXT
            );"#,
        )
        .execute(&mut conn)
        .await?;
    }
    let current_dir_len = current_dir.to_str().unwrap().len();

    let (directories, approximately_file_num) = iter_directory(&current_dir)?;
    let mut current_progress = 0u32;
    let mut last_filename_length = 0;
    println!();
    for dir in directories {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let path_str = path.to_str().unwrap();
            if path.is_dir() {
                continue;
            }

            let file_name = path
                .file_name()
                .ok_or("No filename")
                .expect("Get filename fail");
            let file_name_str = file_name.to_str().unwrap_or("");

            current_progress += 1;
            if vec![".py", ".db", ".json", ".exe", ".o", "db-wal", "db-shm"]
                .into_iter()
                .any(|x| path_str.ends_with(x))
            {
                //println!("Skipped: {:?}", file_name);
                continue;
            }
            print!(
                "\r({}/{}), name: {}",
                current_progress,
                approximately_file_num,
                file_name_str
            );
            let c = file_name_str.len();
            if last_filename_length > c {
                let mut s: Vec<char> = Default::default();
                s.resize(last_filename_length - c, ' ');
                print!("{}", s.into_iter().collect::<String>())
            }
            last_filename_length = c;

            std::io::stdout().flush()?;
            if let Ok(rows) = sqlx::query(r#"SELECT 1 FROM "files" WHERE "path" = ?"#)
                .bind(path.to_str().unwrap().to_string())
                .fetch_all(&mut conn)
                .await
            {
                if !rows.is_empty() {
                    continue;
                }
            }

            let file_size = entry.metadata()?.len();

          let rows = sqlx::query_as::<_, (String, i64, Option<String>, Option<String>)>(r#"SELECT * FROM "files" WHERE "size" = ?"#)
                .bind(file_size as i64)
                .fetch_all(&mut conn)
                .await?;
            if rows.is_empty() {
                sqlx::query(r#"INSERT INTO "files" ("path", "size") VALUES (?, ?)"#)
                    .bind(path.to_str().unwrap().to_string())
                    .bind(file_size as i64)
                    .execute(&mut conn)
                    .await?;
                continue;
            }
            let mut dup = false;

            let p_hash = match get_file_sha256(&path, PEEK_SIZE).await {
                Some(s) => s,
                None => continue,
            };

            for row in rows {
                if row.0.eq(path_str) {
                    continue;
                }
                let h_hash = if row.2.is_some() {
                    row.2.clone().unwrap()
                } else if let Some(hash) =
                    get_file_sha256(&PathBuf::from_str(&row.0).unwrap(), PEEK_SIZE).await
                {
                    sqlx::query(r#"UPDATE "files" SET "hhash" = ? WHERE "path" = ?"#)
                        .bind(hash.clone())
                        .bind(row.0.clone())
                        .execute(&mut conn)
                        .await?;
                    hash
                } else {
                    continue
                };
                dup = h_hash.eq(&p_hash);
                if dup {
                    break
                }
            }

            let rows = sqlx::query_as::<_, (String, i64, String, Option<String>)>(
                r#"SELECT * FROM "files" WHERE "size" = ? AND "hhash" = ?"#,
            )
            .bind(file_size as i64)
            .bind(p_hash.clone())
            .fetch_all(&mut conn)
            .await?;
            if rows.is_empty() {
                sqlx::query(r#"INSERT INTO "files" ("path", "size", "hhash") VALUES (?, ?, ?)"#)
                    .bind(path.to_str().unwrap().to_string())
                    .bind(file_size as i64)
                    .bind(p_hash)
                    .execute(&mut conn)
                    .await?;
                continue;
            }
            let hash = match get_file_sha256(&path, MAX_SIZE_LIMIT).await {
                Some(hash) => hash,
                None => continue,
            };
            for row in rows {
                if row.0.eq(path_str) {
                    continue;
                }
                let l_hash = if row.3.is_some() {
                    row.3.clone().unwrap()
                } else if let Some(hash) =
                    get_file_sha256(&PathBuf::from_str(&row.0).unwrap(), MAX_SIZE_LIMIT).await
                {
                    sqlx::query(r#"UPDATE "files" SET "hash" = ? WHERE "path" = ?"#)
                        .bind(hash.clone())
                        .bind(row.0.clone())
                        .execute(&mut conn)
                        .await?;
                    hash
                } else {
                    continue;
                };
                dup = l_hash.eq(&hash);
                if dup {
                    break
                }
            }
            let file_name = file_name_str.to_string();

            if dup {
                let target = path
                    .clone()
                    .to_str()
                    .unwrap()
                    .to_string()
                    .split_at(current_dir_len + 1)
                    .1
                    .replace(if cfg!(windows) { '\\' } else { '/' }, "[0x44]");
                let prefix = PathBuf::from("samehash");
                let rename_target = prefix.join(hash.clone()).join(target.clone());
                println!(
                    "\rFind duplicate file: {}, move to: {:?}",
                    file_name,
                    rename_target.clone()
                );
                create_dir(hash.clone().as_str(), Option::from("samehash"));
                fs::rename(path, rename_target).unwrap();
                num += 1;
            } else {
                sqlx::query(r#"INSERT INTO "files" VALUES (?, ?, ?, ?)"#)
                    .bind(path.to_str().unwrap().to_string())
                    .bind(file_size as i64)
                    .bind(p_hash)
                    .bind(hash)
                    .execute(&mut conn)
                    .await?;
            }
        }
    }
    println!();
    Ok(num)
}

fn create_dir(p: &str, d: Option<&str>) {
    let path = PathBuf::from(d.unwrap_or(".")).join(p);
    match fs::create_dir(path) {
        Ok(_) => {}
        Err(e) => match e.kind() {
            ErrorKind::AlreadyExists => {}
            _ => panic!("Fatal error: {:?}", e),
        },
    }
}

fn revert_function() -> Result<()> {
    for entry in fs::read_dir("samehash")? {
        let path = entry?.path();
        for item in fs::read_dir(path)? {
            let item = item?;
            let filename = item
                .file_name()
                .to_str()
                .unwrap()
                .to_string()
                .replace("[0x44]", if cfg!(windows) { "\\" } else { "/" });
            let target = std::path::Path::new(".").join(&filename);
            fs::rename(item.path(), target)?;
            println!("Move {:?} to {}", item.file_name(), filename)
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::OpenOptions;

    fn write_file(file_name: &str, bytes: usize) -> Result<()> {
        let s = std::iter::repeat("\0").take(bytes).collect::<String>();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(Path::join(Path::new("."), file_name))?;
        file.write(s.as_bytes())?;
        Ok(())
    }

    fn main_test() -> Result<u64> {
        let test_dir = Path::new("test");
        if test_dir.exists() {
            fs::remove_dir_all(test_dir)?;
        }

        fs::create_dir(test_dir)?;
        std::env::set_current_dir(test_dir)?;
        fs::create_dir(Path::new("samehash"))?;
        write_file("1.txt", 5)?;
        write_file("2.txt", 5)?;
        write_file("3.txt", 5)?;
        write_file("4.txt", 5)?;
        write_file("5.txt", 6)?;
        write_file("114514.txt", 2048)?;
        write_file("9.txt", 2048)?;
        fs::create_dir(Path::new("subdir"))?;
        write_file(
            Path::new("subdir").join("1919.txt").to_str().unwrap(),
            2048 * 10,
        )?;
        write_file(
            Path::new("subdir").join("810.txt").to_str().unwrap(),
            2048 * 10,
        )?;
        let current_env = env::current_dir()?;
        let r = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(iter_files(current_env, Some(DEFAULT_DATABASE_FILE)))?;
        Ok(r)
    }

    #[test]
    fn test() {
        assert_eq!(main_test().unwrap(), 5);
    }

    #[test]
    fn test_duplicate_run() {
        let r = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(iter_files(
                env::current_dir().unwrap(),
                Some(DEFAULT_DATABASE_FILE),
            ))
            .unwrap();
        assert_eq!(r, 0);
    }

    #[test]
    fn test_revert() {
        let cwd = std::env::current_dir().unwrap();
        if !cwd.ends_with("test") {
            panic!("Should specify `--test-threads=1' in args")
        }
        revert_function().unwrap();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().into_iter().any(|x| x.eq("--revert")) {
        return revert_function();
    }

    let cwd = env::current_dir().unwrap();
    create_dir("samehash", None);
    println!("Current path: {}", cwd.to_str().unwrap());
    let start_time = std::time::Instant::now();
    iter_files(cwd, {
        if std::env::args().into_iter().any(|x| x.eq("--memory")) {
            None
        } else {
            Some(DEFAULT_DATABASE_FILE)
        }
    })
    .await?;

    let elapsed = start_time.elapsed();
    let (t, suffix) = if elapsed.as_millis() > 1000 {
        (elapsed.as_secs(), "seconds")
    } else {
        (elapsed.as_millis() as u64, "milliseconds")
    };
    println!(
        "Time elapsed: {} {}",
        t,
        suffix
    );
    pause();
    Ok(())
}
