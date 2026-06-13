//src/db/conn.rs

use rusqlite::{ params, Connection, Result };
use rusqlite_migration::{ Migrations, M };
use dotenv::dotenv;
use std::env;
use std::error::Error;

pub fn init_db() -> Result<Connection, Box<dyn Error>> {
    dotenv().ok();

    // opens the db file. If its not found, it creates one.
    let mut conn = Connection::open("data.db")?;

    // encryption key
    let key: String = env::var("SQL_KEY").expect("[ERROR] SQL_KEY must be set in .env");

    // migrations
    apply_migrations(&mut conn, &key)?;
    Ok(conn);
}

fn apply_migrations(conn: &mut Connection, key: &str) -> Result<(), Box<dyn Error>> {
    conn.pragma_update(None, "key", key)?;

    let migrations = Migrations::new(vec![
        M::up("CREATE TABLE entries (id INTEGER PRIMARY KEY, name TEXT NOT NULL, filename TEXT) ")
    ]);

    migrations.to_latest(conn)?;
    Ok(());
}