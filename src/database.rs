/*
 ** Copyright (C) 2021 KunoiSayami
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
#![allow(dead_code)]
const SELECT_STATEMENT: &str = r#"SELECT "value" FROM "fdc_meta" WHERE "key" = 'version'"#;

pub static MEMORY_DATABASE: LazyLock<String> = LazyLock::new(|| "sqlite::memory:".to_string());

pub mod v5 {

    use sqlx::{query_as, SqliteConnection};

    pub const CREATE_TABLE: &str = r#"CREATE TABLE "files" (
            "path"	TEXT NOT NULL,
            "size"	INTEGER NOT NULL,
            "head_hash"	TEXT,
            "hash"	TEXT
        );

        CREATE TABLE "fdc_meta" (
            "key"	TEXT NOT NULL,
            "value"	TEXT NOT NULL,
            PRIMARY KEY("key")
        );

        CREATE TABLE "file_mapping" (
            "key"   TEXT NOT NULL,
            "target" TEXT NOT NULL,
            PRIMARY KEY("key")
        );

        CREATE TABLE "directory" (
            "directory" TEXT NOT NULL
        );

        INSERT INTO "fdc_meta" VALUES ("version", "5");
        "#;

    pub const VERSION: &str = "5";

    pub const CREATE_DIRECTORY_TABLE: &str = r#"

    CREATE TABLE "directory" (
        "directory" TEXT NOT NULL
    );

    "#;

    pub async fn check_database_version(conn: &mut SqliteConnection) -> sqlx::Result<String> {
        if let Some((v,)) =
            query_as::<_, (String,)>(r#"SELECT "value" FROM "fdc_meta" WHERE "key" = 'version'"#)
                .fetch_optional(conn)
                .await?
        {
            Ok(v)
        } else {
            Ok(VERSION.to_string())
        }
    }
}

pub const MAJOR_DATABASE_VERSION: &str = current::VERSION;
use std::path::PathBuf;
use std::sync::LazyLock;

use anyhow::anyhow;
pub use current::check_database_version;
use sqlx::prelude::FromRow;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, SqliteConnection};
pub use v5 as current;
use xxhash_rust::xxh3::xxh3_64;

pub async fn get_string_hash(s: &str) -> String {
    xxh3_64(s.as_bytes()).to_string()
}

#[derive(Debug)]
pub enum VersionResult {
    Equal,
    Mismatch(String),
}

impl From<&str> for VersionResult {
    fn from(version: &str) -> Self {
        if version.eq(MAJOR_DATABASE_VERSION) {
            VersionResult::Equal
        } else {
            VersionResult::Mismatch(version.to_string())
        }
    }
}

impl From<&String> for VersionResult {
    fn from(version: &String) -> Self {
        Self::from(version.as_str())
    }
}

pub async fn check_version_eq_major(conn: &mut SqliteConnection) -> sqlx::Result<VersionResult> {
    let version = check_database_version(conn).await?;
    Ok(VersionResult::from(&version))
}

#[derive(Clone, Debug, FromRow)]
pub struct FileInfo {
    path: String,
    size: i64,
    head_hash: Option<String>,
    hash: Option<String>,
}

impl FileInfo {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn size(&self) -> i64 {
        self.size
    }

    pub fn hash(&self) -> Option<&String> {
        self.hash.as_ref()
    }

    pub fn head_hash(&self) -> Option<&String> {
        self.head_hash.as_ref()
    }
}

#[derive(Debug)]
pub struct SqliteHelper {
    conn: SqliteConnection,
}

impl SqliteHelper {
    pub async fn new(filename: &str) -> sqlx::Result<Self> {
        let opt = SqliteConnectOptions::new()
            .create_if_missing(true)
            .in_memory(filename.eq("sqlite::memory:"))
            .filename(filename);
        let conn = SqliteConnection::connect_with(&opt).await?;
        Ok(Self { conn })
    }

    pub async fn create_table(&mut self) -> sqlx::Result<()> {
        if sqlx::query(r#"SELECT name FROM sqlite_master WHERE type='table' AND "name"='files'"#)
            .fetch_all(&mut self.conn)
            .await?
            .is_empty()
        {
            sqlx::query(current::CREATE_TABLE)
                .execute(&mut self.conn)
                .await?;
        } else if let VersionResult::Mismatch(version) =
            check_version_eq_major(&mut self.conn).await?
        {
            panic!("Except database version {MAJOR_DATABASE_VERSION}, but {version} found");
        }
        Ok(())
    }

    pub async fn check_work_dir(&mut self, current_directory: &str) -> sqlx::Result<bool> {
        let ret =
            sqlx::query_as::<_, (String,)>(r#"SELECT "value" FROM "fdc_meta" WHERE "key" = ?"#)
                .bind("working_directory")
                .fetch_optional(&mut self.conn)
                .await?;
        if ret.as_ref().is_some_and(|(s,)| s.eq(current_directory)) {
            return Ok(true);
        }

        sqlx::query(if ret.is_some() {
            r#"UPDATE "fdc_meta" SET "value" = ? WHERE "key" = 'working_directory'"#
        } else {
            r#"INSERT INTO "fdc_meta" VALUES ('working_directory', ?)"#
        })
        .bind(current_directory)
        .execute(&mut self.conn)
        .await?;
        Ok(false)
    }

    pub async fn init_new_directory(
        &mut self,
        directories: &[PathBuf],
        total: i64,
    ) -> anyhow::Result<Vec<String>> {
        sqlx::query(r#"DROP TABLE "directory""#)
            .execute(&mut self.conn)
            .await?;
        sqlx::query(r#"DELETE FROM "fdc_meta" WHERE "key" = 'total_num' "#)
            .execute(&mut self.conn)
            .await?;
        sqlx::query(current::CREATE_DIRECTORY_TABLE)
            .execute(&mut self.conn)
            .await?;
        let directories = directories
            .iter()
            .map(|x| {
                x.to_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| anyhow!("Unable convert PathBuf to string"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        for directory in &directories {
            sqlx::query(r#"INSERT INTO "directory" VALUES (?)"#)
                .bind(directory)
                .execute(&mut self.conn)
                .await?;
        }
        sqlx::query(r#"INSERT INTO "fdc_meta" VALUES (?, ?)"#)
            .bind("total_num")
            .bind(total.to_string())
            .execute(&mut self.conn)
            .await?;
        Ok(directories)
    }

    pub async fn fetch_meta(&mut self) -> sqlx::Result<(Vec<String>, i64)> {
        let directories = sqlx::query_as::<_, (String,)>(r#"SELECT * FROM "directory""#)
            .fetch_all(&mut self.conn)
            .await?;
        let num = sqlx::query_as::<_, (String,)>(
            r#"SELECT "value" FROM "fdc_meta" WHERE "key" = 'total_num'"#,
        )
        .fetch_optional(&mut self.conn)
        .await?
        .map(|s| s.0);
        Ok((
            directories.iter().map(|x| x.0.clone()).collect(),
            num.as_deref().unwrap_or("0").parse().unwrap_or(0),
        ))
    }

    pub async fn check_dir_empty(&mut self, path: &str) -> sqlx::Result<bool> {
        sqlx::query(r#"SELECT 1 FROM "files" WHERE "path" = ?"#)
            .bind(path)
            .fetch_all(&mut self.conn)
            .await
            .map(|v| v.is_empty())
    }

    pub async fn select_file_by_size(&mut self, size: i64) -> sqlx::Result<Vec<FileInfo>> {
        sqlx::query_as(r#"SELECT * FROM "files" WHERE "size" = ?"#)
            .bind(size)
            .fetch_all(&mut self.conn)
            .await
    }

    pub async fn insert_file(
        &mut self,
        path: &str,
        size: i64,
        head_hash: Option<&String>,
        hash: Option<&String>,
    ) -> sqlx::Result<()> {
        sqlx::query(
            r#"INSERT INTO "files" ("path", "size", "head_hash", "hash") VALUES (?, ?, ?, ?)"#,
        )
        .bind(path)
        .bind(size)
        .bind(head_hash)
        .bind(hash)
        .execute(&mut self.conn)
        .await?;
        Ok(())
    }

    pub async fn update_file_head_hash(&mut self, path: &str, hash: &str) -> sqlx::Result<()> {
        sqlx::query(r#"UPDATE "files" SET "head_hash" = ? WHERE "path" = ?"#)
            .bind(hash)
            .bind(path)
            .execute(&mut self.conn)
            .await?;
        Ok(())
    }

    pub async fn select_file_by_size_hash(
        &mut self,
        size: i64,
        head_hash: &str,
    ) -> sqlx::Result<Vec<FileInfo>> {
        sqlx::query_as(r#"SELECT * FROM "files" WHERE "size" = ? AND "head_hash" = ? "#)
            .bind(size)
            .bind(head_hash)
            .fetch_all(&mut self.conn)
            .await
    }
    pub async fn update_file_hash(&mut self, path: &str, hash: &str) -> sqlx::Result<()> {
        sqlx::query(r#"UPDATE "files" SET "hash" = ? WHERE "path" = ?"#)
            .bind(hash)
            .bind(path)
            .execute(&mut self.conn)
            .await?;
        Ok(())
    }

    pub async fn insert_file_mapping(&mut self, hash: &str, to: &str) -> sqlx::Result<()> {
        sqlx::query(r#"INSERT INTO "file_mapping" VALUES (?, ?)"#)
            .bind(hash)
            .bind(to)
            .execute(&mut self.conn)
            .await?;
        Ok(())
    }

    pub async fn clear_working_table(&mut self, directory: &str) -> sqlx::Result<()> {
        sqlx::query(r#"DELETE FROM "directory" WHERE "directory" = ? "#)
            .bind(directory)
            .execute(&mut self.conn)
            .await?;
        Ok(())
    }
}
