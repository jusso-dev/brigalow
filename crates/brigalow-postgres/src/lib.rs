//! Postgres-only SQLx surface. No optional SQLite/MySQL drivers or query macros.
//! Keep SQLx's actual drivers, transactions and migration engine; this only re-exports APIs.
pub use sqlx_core::{
    connection::{ConnectOptions, Connection},
    error::{Error, Result},
    executor::Executor,
    migrate,
    query::query,
    query_as::query_as,
    query_scalar::query_scalar,
    raw_sql::raw_sql,
    row::Row,
    sql_str::{AssertSqlSafe, SqlSafeStr},
    transaction::Transaction,
    types,
};
pub use sqlx_postgres::{self as postgres, PgConnection, PgPool, Postgres};
