// SQLite schema initialization for BlkBox

use rusqlite::{Connection, Result};

/// Initialize the database schema
/// Creates all tables if they don't exist and applies migrations
pub fn initialize_schema(conn: &Connection) -> Result<()> {
    // Create base tables
    create_base_tables(conn)?;

    // Apply migrations for additional tables
    super::migrations::migrate_database(conn)?;

    Ok(())
}

/// Create base tables that existed before migration system
fn create_base_tables(conn: &Connection) -> Result<()> {
    // Attacks table - stores all attack events
    conn.execute(
        "CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            source_port INTEGER NOT NULL,
            service_type TEXT NOT NULL,
            service_id INTEGER NOT NULL,
            user_agent TEXT,
            payload TEXT NOT NULL,
            threat_level INTEGER NOT NULL DEFAULT 0,
            fingerprint TEXT,
            geolocation TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    // Sessions table - tracks attack sessions over time
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_id INTEGER NOT NULL,
            session_token TEXT,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            commands TEXT,
            queries TEXT,
            files_accessed TEXT,
            FOREIGN KEY(attack_id) REFERENCES attacks(id)
        )",
        [],
    )?;

    // Payloads table - stores strikeback payloads
    conn.execute(
        "CREATE TABLE IF NOT EXISTS payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload_id TEXT UNIQUE NOT NULL,
            payload_type TEXT NOT NULL,
            content BLOB NOT NULL,
            target_ip TEXT NOT NULL,
            deployed_at TEXT NOT NULL,
            executed BOOLEAN DEFAULT 0,
            callback_received BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    // Intelligence table - stores data collected from payloads
    conn.execute(
        "CREATE TABLE IF NOT EXISTS intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload_id TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            data_type TEXT NOT NULL,
            data TEXT NOT NULL,
            collected_at TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(payload_id) REFERENCES payloads(payload_id)
        )",
        [],
    )?;

    // Fingerprints table - stores attacker fingerprints
    conn.execute(
        "CREATE TABLE IF NOT EXISTS fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_id INTEGER NOT NULL,
            fingerprint_type TEXT NOT NULL,
            fingerprint_value TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(attack_id) REFERENCES attacks(id)
        )",
        [],
    )?;

    // Create indexes for common queries
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attacks_source_ip ON attacks(source_ip)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attacks_service_type ON attacks(service_type)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_sessions_attack_id ON sessions(attack_id)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_payloads_target_ip ON payloads(target_ip)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_intelligence_payload_id ON intelligence(payload_id)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_fingerprints_attack_id ON fingerprints(attack_id)",
        [],
    )?;

    Ok(())
}


/// Drop all tables (for testing/reset)
#[allow(dead_code)]
pub fn drop_schema(conn: &Connection) -> Result<()> {
    conn.execute("DROP TABLE IF EXISTS fingerprints", [])?;
    conn.execute("DROP TABLE IF EXISTS intelligence", [])?;
    conn.execute("DROP TABLE IF EXISTS payloads", [])?;
    conn.execute("DROP TABLE IF EXISTS sessions", [])?;
    conn.execute("DROP TABLE IF EXISTS attacks", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_initialization() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        // Verify tables exist by querying sqlite_master
        let table_count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('attacks', 'sessions', 'payloads', 'intelligence', 'fingerprints')",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(table_count, 5);
    }

    #[test]
    fn test_drop_schema() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();
        drop_schema(&conn).unwrap();

        // Verify tables are dropped
        let table_count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('attacks', 'sessions', 'payloads', 'intelligence', 'fingerprints')",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(table_count, 0);
    }
}
