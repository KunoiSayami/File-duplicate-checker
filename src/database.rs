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

mod v2 {

    use sqlx::{query_as, SqliteConnection, query};
    use anyhow::Result;

    const CREATE_TABLE: &str =
        r#"CREATE TABLE "files" (
            "path"	TEXT NOT NULL,
            "size"	INTEGER NOT NULL,
            "hhash"	TEXT,
            "hash"	TEXT
        );

        CREATE TABLE "fdc_meta" (
            "key"	TEXT NOT NULL,
            "value"	TEXT NOT NULL,
            PRIMARY KEY("key")
        );"#;
    const INIT_TABLE: &str =
        r#"INSERT INTO "fdc_meta" VALUES ("version", "2")"#;

    const VERSION: &str = "2";

    async fn upgrade_from_v0(mut conn: SqliteConnection) -> Result<SqliteConnection> {

        query(r#"ALTER TABLE "files" RENAME TO "old_files"#)
            .execute(&mut conn)
            .await?;

        query(CREATE_TABLE)
            .execute(&mut conn)
            .await?;

        for row in query_as::<_, (String, i64, String, Option<String>)>(r#"SELECT * FROM "old_files""#)
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
}