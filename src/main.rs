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
const DEFAULT_MAX_SIZE_LIMIT: usize = usize::MAX;
const DEFAULT_DATABASE_FILE: &str = "samehash.db";
const DEFAULT_FOLDER: &str = "samehash";
const PEEK_SIZE: usize = BUFFER_SIZE * 8;
const PROGRAM_VERSION: &'static str = env!("CARGO_PKG_VERSION");

// https://www.reddit.com/r/rust/comments/8tfyof/noob_question_pause/
fn pause() {
    let mut stdout = stdout();
    stdout.write_all(b"Press Enter to continue...").unwrap();
    stdout.flush().unwrap();
    std::io::Read::read(&mut stdin(), &mut [0]).unwrap();
}

async fn get_file_sha256sum(path: &Path, read_size: usize) -> Result<String> {
    let file = match File::open(&path).await {
        Ok(file) => file,
        Err(error) => {
            eprintln!("Open {:?} error {:?}", path, error);
            return Err(anyhow::Error::from(error));
        }
    };
    let mut file = BufReader::new(file);
    let mut sha256 = Sha256::new();
    let mut buffer = [0; BUFFER_SIZE];
    let mut rsize = 0usize;
    loop {
        let size = file.read(&mut buffer).await.ok().unwrap();
        DynDigest::update(&mut sha256, &buffer[0..size]);
        rsize += size;
        if size < BUFFER_SIZE || rsize > read_size {
            break;
        }
    }
    let result = sha256.finalize();
    Ok(format!("{:x}", result))
}

fn iter_directory(dir: &Path) -> Result<(Vec<PathBuf>, u32)> {
    let mut files = 0u32;
    let mut dirs = vec![dir.to_path_buf()];
    let current_dir = dir;
    let mut skipped: Vec<String> = Default::default();
    match fs::read_dir(current_dir) {
        Ok(read_dir) => {
            for entry in read_dir {
                let entry = entry?;
                let path = entry.path();
                let path_str = path.to_str().unwrap();
                if path.is_dir() {
                    if vec![".git", "target", DEFAULT_FOLDER]
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
        }
        Err(e) => {
            eprintln!("Got error in {:?}, {:?}", current_dir, e)
        }
    }
    Ok((dirs, files))
}

async fn iter_files(current_dir: PathBuf, path_db: Option<&str>, apply_move: bool) -> Result<u64> {
    if !apply_move {
        eprintln!("WARNING: dry run is specified")
    }
    let max_size_limit: usize = option_env!("max_size_limit")
        .unwrap_or("")
        .parse::<usize>()
        .unwrap_or(DEFAULT_MAX_SIZE_LIMIT);
    if max_size_limit != DEFAULT_MAX_SIZE_LIMIT {
        println!(
            "max_size_limit specified in environment variable: {}",
            max_size_limit
        )
    }
    let mut num = 0u64;
    if path_db.is_some() {
        let file = std::path::Path::new(path_db.clone().unwrap());
        if !file.exists() {
            std::fs::File::create(file)?;
        }
    }
    let mut conn = SqliteConnection::connect(path_db.unwrap_or("sqlite::memory:")).await?;
    let mut conn =
        if sqlx::query(r#"SELECT name FROM sqlite_master WHERE type='table' AND "name"='files'"#)
            .fetch_all(&mut conn)
            .await?
            .is_empty()
        {
            sqlx::query(database::v2::CREATE_TABLE)
                .execute(&mut conn)
                .await?;
            conn
        } else {
            let (conn, result) = database::check_version_eq_major(conn).await?;
            if let database::VersionResult::Mismatch(version) = result {
                panic!(
                    "Except database version {}, but {} found",
                    database::MAJOR_DATABASE_VERSION,
                    version
                );
            }
            conn
        };
    println!("Current path: {}", current_dir.to_str().unwrap());
    let current_dir_len = current_dir.to_str().unwrap().len();

    let (directories, approximately_file_num) = iter_directory(&current_dir)?;
    let mut current_progress = 0u32;
    let mut last_filename_length = 0;
    println!();
    for dir in directories {
        let read_dir = fs::read_dir(&dir);
        if read_dir.is_err() {
            let err = read_dir.unwrap_err();
            eprintln!("\nRead directory error: {:?} ({:?})", &dir, err);
            continue;
        }
        for entry in read_dir? {
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
            let file_name_str = if file_name_str.len() > 20 {
                file_name_str.split_at(20).0
            } else {
                file_name_str
            };

            current_progress += 1;
            if vec![".py", ".db", ".json", ".exe", ".o", "db-wal", "db-shm"]
                .into_iter()
                .any(|x| path_str.ends_with(x))
            {
                continue;
            }
            print!(
                "\r({}/{}): {}",
                current_progress, approximately_file_num, file_name_str
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

            // META data check
            let file_size = match entry.metadata() {
                Ok(metadata) => metadata.len(),
                Err(e) => {
                    eprintln!("Error in fetch {:?} metadata ({:?})", &path, e);
                    continue;
                }
            };

            let rows = sqlx::query_as::<_, (String, i64, Option<String>, Option<String>)>(
                r#"SELECT * FROM "files" WHERE "size" = ?"#,
            )
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

            // PEEK sha256 check
            let p_hash = match get_file_sha256sum(&path, PEEK_SIZE).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Got file sha256sum error: {:?}, {:?}", &path, e);
                    continue;
                }
            };

            for row in rows {
                if row.0.eq(path_str) {
                    continue;
                }
                let h_hash = if row.2.is_some() {
                    row.2.clone().unwrap()
                } else {
                    match get_file_sha256sum(&PathBuf::from_str(&row.0).unwrap(), PEEK_SIZE).await {
                        Ok(hash) => {
                            sqlx::query(r#"UPDATE "files" SET "hhash" = ? WHERE "path" = ?"#)
                                .bind(hash.clone())
                                .bind(row.0.clone())
                                .execute(&mut conn)
                                .await?;
                            hash
                        }
                        Err(e) => {
                            eprintln!("[History] Got file sha256sum error: {}, {:?}", &row.0, e);
                            continue;
                        }
                    }
                };
                dup = h_hash.eq(&p_hash);
                if dup {
                    break;
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

            // FULL SIZE CHECK
            let hash = match get_file_sha256sum(&path, max_size_limit).await {
                Ok(hash) => hash,
                Err(e) => {
                    eprintln!("Got full file sha256sum error: {:?}, {:?}", &path, e);
                    continue;
                }
            };

            for row in rows {
                if row.0.eq(path_str) {
                    continue;
                }
                let l_hash = if row.3.is_some() {
                    row.3.clone().unwrap()
                } else {
                    match get_file_sha256sum(&PathBuf::from_str(&row.0).unwrap(), max_size_limit)
                        .await
                    {
                        Ok(hash) => {
                            sqlx::query(r#"UPDATE "files" SET "hash" = ? WHERE "path" = ?"#)
                                .bind(hash.clone())
                                .bind(row.0.clone())
                                .execute(&mut conn)
                                .await?;
                            hash
                        }
                        Err(e) => {
                            eprintln!("[History] Got file sha256sum error: {}, {:?}", &row.0, e);
                            continue;
                        }
                    }
                };
                dup = l_hash.eq(&hash);
                if dup {
                    break;
                }
            }
            let file_name = file_name_str.to_string();

            if dup && apply_move {
                let target = path
                    .clone()
                    .to_str()
                    .unwrap()
                    .to_string()
                    .split_at(current_dir_len + 1)
                    .1
                    .replace(if cfg!(windows) { '\\' } else { '/' }, "[0x44]");
                let prefix = PathBuf::from(DEFAULT_FOLDER);
                let rename_target = prefix.join(hash.clone()).join(target.clone());
                println!(
                    "\rFind duplicate file: {}, move to: {:?}",
                    file_name,
                    rename_target.clone()
                );
                create_dir(hash.clone().as_str(), Option::from(DEFAULT_FOLDER));
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
    println!("{:>80}", "");
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
    for entry in fs::read_dir(DEFAULT_FOLDER)? {
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
        fs::create_dir(Path::new(DEFAULT_FOLDER))?;
        write_file("1.txt", 5)?;
        write_file("2.txt", 5)?;
        write_file("3.txt", 5)?;
        write_file("4.txt", 5)?;
        write_file("5.txt", 6)?;
        write_file("6.txt", 2048)?;
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
            .block_on(iter_files(current_env, Some(DEFAULT_DATABASE_FILE), true))?;
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
                true,
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
    println!(
        "Version: {}, Database version: {}",
        PROGRAM_VERSION,
        database::MAJOR_DATABASE_VERSION
    );
    if std::env::args().into_iter().any(|x| x.eq("--revert")) {
        return revert_function();
    }

    if std::env::args().into_iter().any(|x| x.eq("--upgrade-v2")) {
        let conn = SqliteConnection::connect(DEFAULT_DATABASE_FILE).await?;
        database::v2::upgrade_from_v0(conn).await?;
        return Ok(());
    }

    let apply_move = !std::env::args().into_iter().any(|x| x.eq("--dry"));

    let cwd = env::current_dir().unwrap();
    create_dir(DEFAULT_FOLDER, None);
    let start_time = std::time::Instant::now();
    iter_files(
        cwd,
        {
            if std::env::args().into_iter().any(|x| x.eq("--memory")) {
                None
            } else {
                Some(DEFAULT_DATABASE_FILE)
            }
        },
        apply_move,
    )
    .await?;

    let elapsed = start_time.elapsed();
    let (t, suffix) = if elapsed.as_millis() > 1000 {
        (elapsed.as_secs(), "seconds")
    } else {
        (elapsed.as_millis() as u64, "milliseconds")
    };
    println!("Time elapsed: {} {}", t, suffix);
    pause();
    Ok(())
}
