use rusqlite::{Connection, Result};

/// Apply database migrations
pub fn migrate_database(conn: &Connection) -> Result<()> {
    // Create schema_version table if not exists
    create_version_table(conn)?;

    // Get current schema version
    let version = get_schema_version(conn)?;

    println!("Current database schema version: {}", version);

    // Apply migrations in sequence
    if version < 1 {
        println!("Applying migration 001: Add cloudflare_metadata and attack_sessions tables");
        apply_migration_001(conn)?;
        set_schema_version(conn, 1)?;
    }

    if version < 2 {
        println!("Applying migration 002: Add FTP honeypot tables");
        apply_migration_002(conn)?;
        set_schema_version(conn, 2)?;
    }

    println!("Database migrations complete. Current version: {}", get_schema_version(conn)?);

    Ok(())
}

fn create_version_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;
    Ok(())
}

fn apply_migration_001(conn: &Connection) -> Result<()> {
    // Add cloudflare_metadata table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cloudflare_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_id INTEGER NOT NULL,
            cf_ray TEXT,
            cf_connecting_ip TEXT,
            cf_ipcountry TEXT,
            cf_visitor TEXT,
            cf_threat_score INTEGER,
            cf_request_id TEXT,
            cf_colo TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(attack_id) REFERENCES attacks(id)
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cloudflare_attack_id
         ON cloudflare_metadata(attack_id)",
        [],
    )?;

    // Add attack_sessions table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS attack_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_hash TEXT UNIQUE NOT NULL,
            source_ip TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            attack_count INTEGER NOT NULL DEFAULT 1,
            protocol_count INTEGER NOT NULL DEFAULT 1,
            protocols_used TEXT NOT NULL,
            fingerprints TEXT,
            aggregate_threat_level INTEGER DEFAULT 0,
            threat_escalation BOOLEAN DEFAULT 0,
            persistence_score INTEGER DEFAULT 0,
            attack_ids TEXT NOT NULL,
            geolocation TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attack_sessions_source_ip
         ON attack_sessions(source_ip)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attack_sessions_session_hash
         ON attack_sessions(session_hash)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attack_sessions_last_seen
         ON attack_sessions(last_seen)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attack_sessions_threat_level
         ON attack_sessions(aggregate_threat_level)",
        [],
    )?;

    println!("Migration 001 applied successfully");
    Ok(())
}

fn apply_migration_002(conn: &Connection) -> Result<()> {
    // Add ftp_uploads table for quarantined files
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ftp_uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quarantine_id TEXT UNIQUE NOT NULL,
            attack_id INTEGER,
            session_id TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            username TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            quarantine_path TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            md5 TEXT NOT NULL,
            file_type TEXT NOT NULL,
            is_executable BOOLEAN NOT NULL DEFAULT 0,
            is_script BOOLEAN NOT NULL DEFAULT 0,
            is_archive BOOLEAN NOT NULL DEFAULT 0,
            malware_score INTEGER NOT NULL DEFAULT 0,
            uploaded_at TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(attack_id) REFERENCES attacks(id)
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ftp_uploads_source_ip
         ON ftp_uploads(source_ip)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ftp_uploads_sha256
         ON ftp_uploads(sha256)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ftp_uploads_malware_score
         ON ftp_uploads(malware_score)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ftp_uploads_uploaded_at
         ON ftp_uploads(uploaded_at)",
        [],
    )?;

    // Add ftp_sessions table for detailed FTP session tracking
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ftp_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            attack_id INTEGER,
            source_ip TEXT NOT NULL,
            source_port INTEGER NOT NULL,
            username TEXT,
            password TEXT,
            auth_attempts INTEGER NOT NULL DEFAULT 0,
            command_count INTEGER NOT NULL DEFAULT 0,
            bytes_uploaded INTEGER NOT NULL DEFAULT 0,
            bytes_downloaded INTEGER NOT NULL DEFAULT 0,
            files_accessed TEXT,
            commands TEXT,
            uploaded_executables BOOLEAN NOT NULL DEFAULT 0,
            downloaded_sensitive BOOLEAN NOT NULL DEFAULT 0,
            directory_traversal_attempted BOOLEAN NOT NULL DEFAULT 0,
            threat_level INTEGER NOT NULL DEFAULT 0,
            client_fingerprint TEXT,
            session_start TEXT NOT NULL,
            session_end TEXT,
            duration_seconds INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(attack_id) REFERENCES attacks(id)
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ftp_sessions_source_ip
         ON ftp_sessions(source_ip)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ftp_sessions_session_id
         ON ftp_sessions(session_id)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ftp_sessions_threat_level
         ON ftp_sessions(threat_level)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ftp_sessions_session_start
         ON ftp_sessions(session_start)",
        [],
    )?;

    println!("Migration 002 applied successfully");
    Ok(())
}

fn get_schema_version(conn: &Connection) -> Result<i32> {
    let version: Result<i32> = conn.query_row(
        "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
        [],
        |row| row.get(0),
    );

    match version {
        Ok(v) => Ok(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
        Err(e) => Err(e),
    }
}

fn set_schema_version(conn: &Connection, version: i32) -> Result<()> {
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        [version],
    )?;
    Ok(())
}
