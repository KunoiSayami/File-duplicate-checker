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

/*pub mod error {
    use sqlx::SqliteConnection;

    #[derive(Debug)]
    struct VersionCheckError {
        conn: SqliteConnection
    }

    impl std::error::Error for VersionCheckError {}

}*/

pub mod v2 {

    use anyhow::Result;
    use sqlx::{query, query_as, SqliteConnection};
    use std::ops::Index;

    pub const CREATE_TABLE: &str = r#"CREATE TABLE "files" (
            "path"	TEXT NOT NULL,
            "size"	INTEGER NOT NULL,
            "hhash"	TEXT,
            "hash"	TEXT
        );

        CREATE TABLE "fdc_meta" (
            "key"	TEXT NOT NULL,
            "value"	TEXT NOT NULL,
            PRIMARY KEY("key")
        );

        INSERT INTO "fdc_meta" VALUES ("version", "2");
        "#;

    #[deprecated(since = "4.0.0", note = "CREATE_TABLE include this statement")]
    pub const INIT_TABLE: &str = r#"INSERT INTO "fdc_meta" VALUES ("version", "2")"#;

    pub const VERSION: &str = "2";

    pub async fn upgrade_from_v0(conn: SqliteConnection) -> Result<SqliteConnection> {
        let (mut conn, version) = check_database_version(conn).await?;

        if version.as_str().ge(VERSION) {
            //TODO: return Error here
            return Ok(conn);
        }

        query(r#"ALTER TABLE "files" RENAME TO "old_files""#)
            .execute(&mut conn)
            .await?;

        query(CREATE_TABLE).execute(&mut conn).await?;

        for row in
            query_as::<_, (String, i64, String, Option<String>)>(r#"SELECT * FROM "old_files""#)
                .fetch_all(&mut conn)
                .await?
        {
            query(r#"INSERT INTO "files" VALUES (?, ?, ?, ?)"#)
                .bind(row.0)
                .bind(row.1)
                .bind(row.2)
                .bind(row.3)
                .execute(&mut conn)
                .await?;
        }

        query(r#"DROP TABLE "old_files""#)
            .execute(&mut conn)
            .await?;

        Ok(conn)
    }

    pub async fn check_database_version(
        mut conn: SqliteConnection,
    ) -> Result<(SqliteConnection, String)> {
        if let Ok(v) =
            query_as::<_, (String,)>(r#"SELECT "value" FROM "fdc_meta" WHERE "key" = 'version'"#)
                .fetch_all(&mut conn)
                .await
        {
            assert!(!v.is_empty());
            Ok((conn, v.index(0).0.clone()))
        } else {
            Ok((conn, "1".to_string()))
        }
    }
}

pub const MAJOR_DATABASE_VERSION: &str = v2::VERSION;
use sqlx::SqliteConnection;
pub use v2::check_database_version;

#[derive(Debug)]
pub enum VersionResult {
    Equal,
    Mismatch(String),
}

impl VersionResult {
    pub fn new(version: &str) -> Self {
        if version.eq(MAJOR_DATABASE_VERSION) {
            VersionResult::Equal
        } else {
            VersionResult::Mismatch(version.to_string())
        }
    }
}

impl From<&str> for VersionResult {
    fn from(version: &str) -> Self {
        VersionResult::new(version)
    }
}

impl From<&String> for VersionResult {
    fn from(version: &String) -> Self {
        Self::from(version.as_str())
    }
}

pub async fn check_version_eq_major(
    conn: SqliteConnection,
) -> anyhow::Result<(SqliteConnection, VersionResult)> {
    let (conn, version) = check_database_version(conn).await?;
    Ok((conn, VersionResult::from(&version)))
}
