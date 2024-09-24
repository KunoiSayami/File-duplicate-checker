/*
 ** Copyright (C) 2020-2024 KunoiSayami
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

use clap::arg;
use database::{SqliteHelper, MEMORY_DATABASE};
use std::fmt::Debug;
use std::io::{stdin, stdout, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::LazyLock;
use std::{env, fs};
use tap::TapFallible;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, BufReader};
use xxhash_rust::xxh3::Xxh3;

const BUFFER_SIZE: usize = 1024 * 16;
const DEFAULT_MAX_SIZE_LIMIT: usize = usize::MAX;
static DEFAULT_DATABASE_FILE: LazyLock<String> = LazyLock::new(|| "dup-checker.db".to_string());
const DEFAULT_FOLDER: &str = "dup";
const PEEK_SIZE: usize = BUFFER_SIZE * 8;
const IGNORE_EXTENSIONS: &[&str] = &[
    ".py", ".db", ".json", ".exe", ".o", "db-wal", "db-shm", ".dll", ".ini", ".toml", ".so",
    ".java", ".h", ".hpp", ".cpp", ".c", ".html", ".htm",
];
const IGNORE_PATHS_PREFIX: &[&str] = &["."];
const IGNORE_PATHS_SUFFIX: &[&str] = &["target", DEFAULT_FOLDER];
const REPLACE_STR: &str = "-]";

// https://www.reddit.com/r/rust/comments/8tfyof/noob_question_pause/
fn pause() {
    let mut stdout = stdout();
    stdout.write_all(b"Press Enter to continue...").unwrap();
    stdout.flush().unwrap();
    std::io::Read::read(&mut stdin(), &mut [0]).unwrap();
}

async fn get_file_hash<P: AsRef<Path> + Debug>(
    path: P,
    read_size: usize,
) -> anyhow::Result<String> {
    let mut file = BufReader::new(
        File::open(&path)
            .await
            .tap_err(|e| log::error!("Open {path:?} error {e:?}"))?,
    );
    let mut hasher = Xxh3::new();
    let mut buffer = [0; BUFFER_SIZE];
    let mut rsize = 0;
    loop {
        let size = file.read(&mut buffer).await?;
        hasher.update(&buffer);
        rsize += size;
        if size < BUFFER_SIZE || rsize > read_size {
            break;
        }
    }
    Ok(hasher.digest().to_string())
}

fn iter_directory<P: AsRef<Path> + Debug>(dir: &P) -> anyhow::Result<(Vec<PathBuf>, i64)> {
    let mut files = 0;
    let mut dirs = vec![dir.as_ref().to_path_buf()];
    let current_dir = dir;
    let mut skipped = Vec::new();
    match fs::read_dir(current_dir) {
        Ok(mut read_dir) => {
            while let Some(Ok(entry)) = read_dir.next() {
                let path = entry.path();
                let path_str = path.to_str().unwrap();
                if path.is_dir() {
                    if IGNORE_PATHS_SUFFIX.iter().any(|x| path_str.ends_with(x))
                        || IGNORE_PATHS_PREFIX.iter().any(|x| path_str.starts_with(x))
                    {
                        skipped.push(path.to_str().unwrap().to_string());
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
            log::info!("in {dir:?}: ({files})");
            for x in skipped {
                log::info!("Skipped path: {x}");
            }
        }
        Err(e) => {
            eprintln!("Got error in {current_dir:?}, {e:?}")
        }
    }
    Ok((dirs, files))
}

async fn iter_files(
    current_dir: &str,
    path_db: Option<&String>,
    apply_move: bool,
    should_delete: bool,
) -> anyhow::Result<u64> {
    if !apply_move {
        log::warn!("WARNING: dry run is specified")
    }
    let max_size_limit: usize = option_env!("max_size_limit")
        .unwrap_or("")
        .parse::<usize>()
        .unwrap_or(DEFAULT_MAX_SIZE_LIMIT);
    if max_size_limit != DEFAULT_MAX_SIZE_LIMIT {
        log::info!("max_size_limit specified in environment variable: {max_size_limit}")
    }
    let mut num = 0;
    let mut conn = SqliteHelper::new(path_db.unwrap_or(&MEMORY_DATABASE)).await?;
    conn.create_table().await?;

    log::info!("Current path: {current_dir:?}");

    let match_current_directory = conn.check_work_dir(current_dir).await?;

    let (directories, approximately_file_num) = if !match_current_directory {
        let (directories, file_num) = iter_directory(&current_dir)?;

        (
            conn.init_new_directory(&directories, file_num).await?,
            file_num,
        )
    } else {
        conn.fetch_meta().await?
    };

    let mut current_progress = 0;
    let mut last_filename_length = 0;
    println!();
    for dir in directories {
        let mut has_error = false;
        let Ok(mut read_dir) =
            fs::read_dir(&dir).tap_err(|e| log::error!("Read directory error: {dir:?} ({e:?})"))
        else {
            continue;
        };
        while let Some(Ok(entry)) = read_dir.next() {
            log::debug!("{entry:?}");
            let path = entry.path();
            let path_str = path.to_str().unwrap();
            if path.is_dir() {
                continue;
            }

            let file_name = path
                .file_name()
                .ok_or("No filename or directory")
                .expect("Get filename fail");
            let file_name_str = file_name.to_str().unwrap_or("N:A");

            current_progress += 1;

            if IGNORE_EXTENSIONS.iter().any(|x| path_str.ends_with(x)) {
                log::debug!("Skip because extensions");
                continue;
            }

            print!("\r({current_progress}/{approximately_file_num}): {file_name_str}",);
            let c = file_name_str.len();
            if last_filename_length > c {
                let mut s: Vec<char> = Default::default();
                s.resize(last_filename_length - c, ' ');
                print!("{}", s.into_iter().collect::<String>())
            }
            last_filename_length = c;
            std::io::stdout().flush()?;

            if !conn.check_dir_empty(path_str).await? {
                //log::debug!("Skip because folder is empty");
                continue;
            }

            // META data check
            let Ok(file_size) = entry
                .metadata()
                .map(|d| d.len() as i64)
                .tap_err(|e| eprintln!("Error in fetch {path:?} metadata ({e:?})"))
            else {
                has_error = true;
                continue;
            };

            let rows = conn.select_file_by_size(file_size).await?;
            if rows.is_empty() {
                conn.insert_file(path_str, file_size, None, None).await?;
                continue;
            }
            let mut dup = false;

            // PEEK sha256 check
            let file_head_hash = match get_file_hash(&path, PEEK_SIZE).await {
                Ok(s) => s,
                Err(e) => {
                    has_error = true;
                    log::error!("Got file sha256sum error: {path:?}, {e:?}");
                    continue;
                }
            };

            for row in rows {
                if row.path().eq(path_str) {
                    continue;
                }
                let h_hash = if row.head_hash().is_some() {
                    row.head_hash().unwrap()
                } else {
                    &match get_file_hash(row.path(), PEEK_SIZE).await {
                        Ok(hash) => {
                            conn.update_file_head_hash(row.path(), &hash).await?;
                            hash
                        }
                        Err(e) => {
                            log::error!(
                                "[History] Got file sha256sum error: {}, {e:?}",
                                row.path(),
                            );
                            continue;
                        }
                    }
                };
                dup = h_hash.eq(&file_head_hash);
                if dup {
                    break;
                }
            }

            let rows = conn
                .select_file_by_size_hash(file_size, &file_head_hash)
                .await?;
            if rows.is_empty() {
                conn.insert_file(path_str, file_size, Some(&file_head_hash), None)
                    .await?;
                continue;
            }

            // FULL SIZE CHECK
            let hash = match get_file_hash(&path, max_size_limit).await {
                Ok(hash) => hash,
                Err(e) => {
                    has_error = true;
                    log::error!("Got full file sha256sum error: {path:?}, {e:?}");
                    continue;
                }
            };

            for row in rows {
                if row.path().eq(path_str) {
                    continue;
                }
                let l_hash = if row.hash().is_some() {
                    row.hash().unwrap()
                } else {
                    &match get_file_hash(&PathBuf::from_str(row.path()).unwrap(), max_size_limit)
                        .await
                    {
                        Ok(hash) => {
                            conn.update_file_hash(row.path(), &hash).await?;
                            hash
                        }
                        Err(e) => {
                            has_error = true;
                            log::error!(
                                "[History] Got file sha256sum error: {}, {e:?}",
                                row.path(),
                            );
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

            if dup {
                if should_delete {
                    if let Err(e) = fs::remove_file(&path) {
                        has_error = true;
                        log::error!("\rDelete file {path:?} got error: {e:?}",)
                    } else {
                        log::info!("\rFind duplicate file: {path:?}, deleted",)
                    }
                } else if apply_move {
                    let target = path_str
                        .split_at(current_dir.len() + 1)
                        .1
                        .replace(if cfg!(windows) { '\\' } else { '/' }, REPLACE_STR);
                    let prefix = PathBuf::from(DEFAULT_FOLDER);
                    let target_sha = database::get_string_hash(&target).await;
                    conn.insert_file_mapping(&target_sha, &target).await?;
                    let rename_target = prefix.join(hash.clone()).join(target);
                    create_dir(&hash, Some(DEFAULT_FOLDER));
                    //eprintln!("Rename to {rename_target:?}");
                    if let Err(ref e) = fs::rename(path, &rename_target) {
                        has_error = true;
                        log::error!(
                                "\rGot Error while moving duplicate file: {file_name}, cause by {error:?}",
                                error = e,
                            )
                    } else {
                        log::info!("\rFind duplicate file: {file_name}, move to: {rename_target:?}")
                    }
                    num += 1;
                }
            } else {
                conn.insert_file(path_str, file_size, Some(&file_head_hash), Some(&hash))
                    .await?;
            }
        }
        if !has_error {
            conn.clear_working_table(&dir).await?;
        }
    }
    println!("{:>80}", "");
    Ok(num)
}

fn create_dir(p: &str, d: Option<&str>) {
    let path = PathBuf::from(d.unwrap_or(".")).join(p);
    if let Err(e) = fs::create_dir(path) {
        match e.kind() {
            ErrorKind::AlreadyExists => {}
            _ => panic!("Fatal error: {e:?}"),
        }
    }
}

#[allow(dead_code)]
fn revert_function() -> anyhow::Result<()> {
    for entry in fs::read_dir(DEFAULT_FOLDER)? {
        let path = entry?.path();
        for item in fs::read_dir(path)? {
            let item = item?;
            let filename = item
                .file_name()
                .to_str()
                .unwrap()
                .to_string()
                .replace(REPLACE_STR, if cfg!(windows) { "\\" } else { "/" });
            let target = std::path::Path::new(".").join(&filename);
            fs::rename(item.path(), target)?;
            println!("Move {:?} to {filename}", item.file_name())
        }
    }
    Ok(())
}

async fn async_main(
    database: Option<&String>,
    should_delete: bool,
    apply_move: bool,
) -> anyhow::Result<()> {
    let cwd = env::current_dir().unwrap();
    create_dir(DEFAULT_FOLDER, None);
    let start_time = std::time::Instant::now();
    iter_files(cwd.to_str().unwrap(), database, apply_move, should_delete).await?;

    log::info!("Time elapsed: {:?}", start_time.elapsed());
    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_default_env()
        .filter_module("sqlx", log::LevelFilter::Warn)
        .init();

    log::info!(
        "Version: {}, Database version: {}",
        env!("CARGO_PKG_VERSION"),
        database::MAJOR_DATABASE_VERSION
    );

    let matches = clap::command!()
        .args(&[
            arg!([DATABASE] "Database file location").default_value(&**DEFAULT_DATABASE_FILE),
            arg!(--delete "Delete file instead of move"),
            arg!(--dry "Dry run without move"),
            arg!(--memory "Use memory database").conflicts_with("DATABASE"),
        ])
        //.subcommand(clap::Command::new("revert"))
        .get_matches();
    // if std::env::args().into_iter().any(|x| x.eq("--revert")) {
    //     return revert_function();
    // }

    // if std::env::args().into_iter().any(|x| x.eq("--upgrade-v2")) {
    //     let conn = SqliteConnection::connect(DEFAULT_DATABASE_FILE).await?;
    //     database::current::upgrade_from_v0(conn).await?;
    //     return Ok(());
    // }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main(
            if matches.get_flag("memory") {
                None
            } else {
                matches.get_one("DATABASE")
            },
            matches.get_flag("delete"),
            matches.get_flag("dry"),
        ))?;

    pause();
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::OpenOptions;
    use xxhash_rust::xxh3::xxh3_64;

    fn write_file(file_name: &str, bytes: usize) -> anyhow::Result<()> {
        let s = std::iter::repeat("\0").take(bytes).collect::<String>();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(Path::join(Path::new("."), file_name))?;
        file.write(s.as_bytes())?;
        Ok(())
    }

    fn main_test() -> anyhow::Result<u64> {
        //env_logger::Builder::from_default_env().try_init().ok();
        let test_dir = Path::new("test");
        if test_dir.exists() {
            fs::remove_dir_all(test_dir)?;
        }

        fs::create_dir(test_dir)?;
        env::set_current_dir(test_dir)?;
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
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(iter_files(
                current_env.to_str().unwrap(),
                Some(&DEFAULT_DATABASE_FILE),
                true,
                false,
            ))
    }

    #[test]
    fn test() {
        assert_eq!(main_test().unwrap(), 5);
    }

    #[test]
    fn test_duplicate_run() {
        let dir = env::current_dir().unwrap();
        let r = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(iter_files(
                dir.to_str().unwrap(),
                Some(&DEFAULT_DATABASE_FILE),
                true,
                false,
            ))
            .unwrap();
        assert_eq!(r, 0);
    }

    #[test]
    fn test_revert() {
        let cwd = env::current_dir().unwrap();
        if !cwd.ends_with("test") {
            panic!("Should specify `--test-threads=1' in args")
        }
        revert_function().unwrap();
    }

    #[test]
    fn test_xx3hash() {
        const TEST_DATA: [u8; 9] = [0x00, 0x01, 0x02, 0x13, 0xcc, 0xab, 0x03, 0x03, 0x53];
        let mut q = Xxh3::new();
        q.update(&TEST_DATA);
        assert_eq!(q.digest(), xxh3_64(&TEST_DATA));
    }
}
