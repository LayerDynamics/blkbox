// Storage module for SQLite database operations

pub mod schema;
pub mod models;
pub mod operations;
pub mod migrations;

use rusqlite::{Connection, Result};
use std::sync::{Arc, Mutex};
use crate::ffi::types::AttackEvent;
use models::{GeolocationData, FingerprintEntry, CloudflareMetadata, AttackSession};

/// Database wrapper for BlkBox storage
pub struct Database {
    connection: Arc<Mutex<Connection>>,
}

impl Database {
    /// Create a new database connection and initialize schema
    pub fn new(db_path: &str) -> Result<Self> {
        let connection = Connection::open(db_path)?;

        // Initialize schema
        schema::initialize_schema(&connection)?;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Store an attack event in the database
    pub fn store_event(&self, event: &AttackEvent) -> Result<i64> {
        let conn = self.connection.lock().unwrap();

        conn.execute(
            "INSERT INTO attacks (
                timestamp, source_ip, source_port, service_type, service_id,
                user_agent, payload, threat_level, fingerprint
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                event.timestamp,
                event.source_ip,
                event.source_port,
                event.service_type.as_str(),
                event.service_id,
                event.user_agent,
                event.payload,
                event.threat_level,
                event.fingerprint,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Get recent attacks (for testing/debugging)
    pub fn get_recent_attacks(&self, limit: usize) -> Result<Vec<AttackEvent>> {
        let conn = self.connection.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT timestamp, source_ip, source_port, service_type, service_id,
                    user_agent, payload, threat_level, fingerprint
             FROM attacks
             ORDER BY id DESC
             LIMIT ?1"
        )?;

        let events = stmt.query_map([limit], |row| {
            let service_type_str: String = row.get(3)?;
            let service_type = match service_type_str.as_str() {
                "HTTP" => crate::ffi::types::ServiceType::HTTP,
                "HTTPS" => crate::ffi::types::ServiceType::HTTPS,
                "SSH" => crate::ffi::types::ServiceType::SSH,
                "PostgreSQL" => crate::ffi::types::ServiceType::PostgreSQL,
                "MySQL" => crate::ffi::types::ServiceType::MySQL,
                "MongoDB" => crate::ffi::types::ServiceType::MongoDB,
                "FTP" => crate::ffi::types::ServiceType::FTP,
                "SFTP" => crate::ffi::types::ServiceType::SFTP,
                _ => crate::ffi::types::ServiceType::HTTP,
            };

            Ok(AttackEvent {
                timestamp: row.get(0)?,
                source_ip: row.get(1)?,
                source_port: row.get(2)?,
                service_type,
                service_id: row.get(4)?,
                user_agent: row.get(5)?,
                payload: row.get(6)?,
                threat_level: row.get(7)?,
                fingerprint: row.get(8)?,
                cf_metadata: None,
                attack_id: None,
            })
        })?;

        let mut result = Vec::new();
        for event in events {
            result.push(event?);
        }

        Ok(result)
    }

    /// Get total number of attacks
    pub fn get_attack_count(&self) -> Result<i64> {
        let conn = self.connection.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM attacks",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Insert geolocation data for an attack
    pub fn insert_geolocation(&self, attack_id: i64, geo: &GeolocationData) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        operations::insert_geolocation(&conn, attack_id, geo)
    }

    /// Insert fingerprints for an attack
    pub fn insert_fingerprints(&self, attack_id: i64, fingerprints: &[FingerprintEntry]) -> Result<()> {
        let mut conn = self.connection.lock().unwrap();
        operations::insert_fingerprints(&mut conn, attack_id, fingerprints)
    }

    /// Insert Cloudflare metadata for an attack
    pub fn insert_cloudflare_metadata(&self, attack_id: i64, cf: &CloudflareMetadata) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        operations::insert_cloudflare_metadata(&conn, attack_id, cf)
    }

    /// Upsert attack session
    pub fn upsert_attack_session(&self, session: &AttackSession) -> Result<i64> {
        let conn = self.connection.lock().unwrap();
        operations::upsert_attack_session(&conn, session)
    }

    /// Find attack session by hash
    pub fn find_session_by_hash(&self, session_hash: &str) -> Result<Option<AttackSession>> {
        let conn = self.connection.lock().unwrap();
        operations::find_session_by_hash(&conn, session_hash)
    }

    /// Find attack sessions by IP
    pub fn find_sessions_by_ip(&self, ip: &str) -> Result<Vec<AttackSession>> {
        let conn = self.connection.lock().unwrap();
        operations::find_sessions_by_ip(&conn, ip)
    }

    /// Get enriched attack events
    pub fn get_enriched_attacks(&self, limit: usize, offset: usize) -> Result<Vec<models::EnrichedAttackEvent>> {
        let conn = self.connection.lock().unwrap();
        operations::get_enriched_attacks(&conn, limit, offset)
    }

    /// Execute raw SQL statement
    pub fn execute_raw(&self, sql: &str, params: impl rusqlite::Params) -> Result<usize> {
        let conn = self.connection.lock().unwrap();
        Ok(conn.execute(sql, params)?)
    }

    /// Query a single row with raw SQL
    pub fn query_row_raw<T, F>(&self, sql: &str, params: impl rusqlite::Params, f: F) -> Result<T>
    where
        F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        let conn = self.connection.lock().unwrap();
        Ok(conn.query_row(sql, params, f)?)
    }

    /// Execute a closure with access to the raw connection
    /// This is useful for complex operations that need to prepare statements
    pub fn with_connection<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&rusqlite::Connection) -> Result<T>,
    {
        let conn = self.connection.lock().unwrap();
        f(&conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::types::ServiceType;

    #[test]
    fn test_database_creation() {
        let db = Database::new(":memory:").unwrap();
        assert!(db.get_attack_count().unwrap() == 0);
    }

    #[test]
    fn test_store_event() {
        let db = Database::new(":memory:").unwrap();

        let event = AttackEvent::new(
            "1.2.3.4".to_string(),
            12345,
            ServiceType::HTTP,
            1,
        );

        let id = db.store_event(&event).unwrap();
        assert!(id > 0);

        assert_eq!(db.get_attack_count().unwrap(), 1);
    }
}
