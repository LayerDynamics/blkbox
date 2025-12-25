use rusqlite::{Connection, Result, params};
use super::models::*;
use crate::ffi::types::AttackEvent;

/// Insert geolocation data for an attack
pub fn insert_geolocation(
    conn: &Connection,
    attack_id: i64,
    geo: &GeolocationData,
) -> Result<()> {
    let geo_json = serde_json::to_string(geo)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

    conn.execute(
        "UPDATE attacks SET geolocation = ?1 WHERE id = ?2",
        params![geo_json, attack_id],
    )?;

    Ok(())
}

/// Insert multiple fingerprints for an attack
pub fn insert_fingerprints(
    conn: &mut Connection,
    attack_id: i64,
    fingerprints: &[FingerprintEntry],
) -> Result<()> {
    let tx = conn.transaction()?;

    for fp in fingerprints {
        tx.execute(
            "INSERT INTO fingerprints (
                attack_id, fingerprint_type, fingerprint_value, confidence
            ) VALUES (?1, ?2, ?3, ?4)",
            params![
                attack_id,
                fp.fingerprint_type.as_str(),
                fp.value,
                fp.confidence,
            ],
        )?;
    }

    tx.commit()?;
    Ok(())
}

/// Insert Cloudflare metadata
pub fn insert_cloudflare_metadata(
    conn: &Connection,
    attack_id: i64,
    cf: &CloudflareMetadata,
) -> Result<()> {
    conn.execute(
        "INSERT INTO cloudflare_metadata (
            attack_id, cf_ray, cf_connecting_ip, cf_ipcountry,
            cf_visitor, cf_threat_score, cf_request_id, cf_colo
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            attack_id,
            cf.cf_ray,
            cf.cf_connecting_ip,
            cf.cf_ipcountry,
            cf.cf_visitor,
            cf.cf_threat_score,
            cf.cf_request_id,
            cf.cf_colo,
        ],
    )?;

    Ok(())
}

/// Insert or update session data
pub fn upsert_session(
    conn: &Connection,
    session: &SessionData,
) -> Result<i64> {
    let commands_json = serde_json::to_string(&session.commands)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    let queries_json = serde_json::to_string(&session.queries)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    let files_json = serde_json::to_string(&session.files_accessed)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

    conn.execute(
        "INSERT INTO sessions (
            attack_id, session_token, started_at, ended_at,
            commands, queries, files_accessed
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(session_token) DO UPDATE SET
            ended_at = excluded.ended_at,
            commands = excluded.commands,
            queries = excluded.queries,
            files_accessed = excluded.files_accessed",
        params![
            session.attack_id,
            session.session_token,
            session.started_at,
            session.ended_at,
            commands_json,
            queries_json,
            files_json,
        ],
    )?;

    Ok(conn.last_insert_rowid())
}

/// Insert or update attack session
pub fn upsert_attack_session(
    conn: &Connection,
    session: &AttackSession,
) -> Result<i64> {
    let protocols_json = serde_json::to_string(&session.protocols_used)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    let fingerprints_json = serde_json::to_string(&session.fingerprints)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    let attack_ids_json = serde_json::to_string(&session.attack_ids)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

    conn.execute(
        "INSERT INTO attack_sessions (
            session_hash, source_ip, first_seen, last_seen,
            attack_count, protocol_count, protocols_used, fingerprints,
            aggregate_threat_level, threat_escalation, persistence_score,
            attack_ids, geolocation
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
        ON CONFLICT(session_hash) DO UPDATE SET
            last_seen = excluded.last_seen,
            attack_count = excluded.attack_count,
            protocol_count = excluded.protocol_count,
            protocols_used = excluded.protocols_used,
            fingerprints = excluded.fingerprints,
            aggregate_threat_level = excluded.aggregate_threat_level,
            threat_escalation = excluded.threat_escalation,
            persistence_score = excluded.persistence_score,
            attack_ids = excluded.attack_ids,
            updated_at = CURRENT_TIMESTAMP",
        params![
            session.session_hash,
            session.source_ip,
            session.first_seen,
            session.last_seen,
            session.attack_count,
            session.protocol_count,
            protocols_json,
            fingerprints_json,
            session.aggregate_threat_level,
            session.threat_escalation,
            session.persistence_score,
            attack_ids_json,
            session.geolocation,
        ],
    )?;

    Ok(conn.last_insert_rowid())
}

/// Find attack session by hash
pub fn find_session_by_hash(
    conn: &Connection,
    session_hash: &str,
) -> Result<Option<AttackSession>> {
    let mut stmt = conn.prepare(
        "SELECT id, session_hash, source_ip, first_seen, last_seen,
                attack_count, protocol_count, protocols_used, fingerprints,
                aggregate_threat_level, threat_escalation, persistence_score,
                attack_ids, geolocation
         FROM attack_sessions WHERE session_hash = ?1"
    )?;

    let result = stmt.query_row([session_hash], |row| {
        let protocols_json: String = row.get(7)?;
        let fingerprints_json: String = row.get(8)?;
        let attack_ids_json: String = row.get(12)?;

        Ok(AttackSession {
            id: Some(row.get(0)?),
            session_hash: row.get(1)?,
            source_ip: row.get(2)?,
            first_seen: row.get(3)?,
            last_seen: row.get(4)?,
            attack_count: row.get(5)?,
            protocol_count: row.get(6)?,
            protocols_used: serde_json::from_str(&protocols_json).unwrap_or_default(),
            fingerprints: serde_json::from_str(&fingerprints_json).unwrap_or_default(),
            aggregate_threat_level: row.get(9)?,
            threat_escalation: row.get(10)?,
            persistence_score: row.get(11)?,
            attack_ids: serde_json::from_str(&attack_ids_json).unwrap_or_default(),
            geolocation: row.get(13)?,
        })
    });

    match result {
        Ok(session) => Ok(Some(session)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Find attack sessions by IP
pub fn find_sessions_by_ip(
    conn: &Connection,
    ip: &str,
) -> Result<Vec<AttackSession>> {
    let mut stmt = conn.prepare(
        "SELECT id, session_hash, source_ip, first_seen, last_seen,
                attack_count, protocol_count, protocols_used, fingerprints,
                aggregate_threat_level, threat_escalation, persistence_score,
                attack_ids, geolocation
         FROM attack_sessions WHERE source_ip = ?1
         ORDER BY last_seen DESC"
    )?;

    let sessions = stmt.query_map([ip], |row| {
        let protocols_json: String = row.get(7)?;
        let fingerprints_json: String = row.get(8)?;
        let attack_ids_json: String = row.get(12)?;

        Ok(AttackSession {
            id: Some(row.get(0)?),
            session_hash: row.get(1)?,
            source_ip: row.get(2)?,
            first_seen: row.get(3)?,
            last_seen: row.get(4)?,
            attack_count: row.get(5)?,
            protocol_count: row.get(6)?,
            protocols_used: serde_json::from_str(&protocols_json).unwrap_or_default(),
            fingerprints: serde_json::from_str(&fingerprints_json).unwrap_or_default(),
            aggregate_threat_level: row.get(9)?,
            threat_escalation: row.get(10)?,
            persistence_score: row.get(11)?,
            attack_ids: serde_json::from_str(&attack_ids_json).unwrap_or_default(),
            geolocation: row.get(13)?,
        })
    })?
    .collect::<Result<Vec<_>>>()?;

    Ok(sessions)
}

/// Get enriched attack events with all joined data
pub fn get_enriched_attacks(
    conn: &Connection,
    limit: usize,
    offset: usize,
) -> Result<Vec<EnrichedAttackEvent>> {
    let mut stmt = conn.prepare(
        "SELECT
            a.id, a.timestamp, a.source_ip, a.source_port,
            a.service_type, a.service_id, a.user_agent,
            a.payload, a.threat_level, a.fingerprint, a.geolocation
        FROM attacks a
        ORDER BY a.id DESC
        LIMIT ?1 OFFSET ?2"
    )?;

    let rows = stmt.query_map(params![limit, offset], |row| {
        let attack_id: i64 = row.get(0)?;

        // Build base attack event
        let service_type_str: String = row.get(4)?;
        let service_type = match service_type_str.as_str() {
            "HTTP" => crate::ffi::types::ServiceType::HTTP,
            "SSH" => crate::ffi::types::ServiceType::SSH,
            "PostgreSQL" => crate::ffi::types::ServiceType::PostgreSQL,
            "MySQL" => crate::ffi::types::ServiceType::MySQL,
            "MongoDB" => crate::ffi::types::ServiceType::MongoDB,
            "FTP" => crate::ffi::types::ServiceType::FTP,
            _ => crate::ffi::types::ServiceType::HTTP,
        };

        let attack = AttackEvent {
            timestamp: row.get(1)?,
            source_ip: row.get(2)?,
            source_port: row.get(3)?,
            service_type,
            service_id: row.get(5)?,
            user_agent: row.get(6)?,
            payload: row.get(7)?,
            threat_level: row.get(8)?,
            fingerprint: row.get(9)?,
            cf_metadata: None,
            attack_id: row.get::<_, String>(0).ok(),
        };

        // Parse geolocation JSON
        let geo_json: Option<String> = row.get(10)?;
        let geolocation = geo_json.and_then(|json| {
            serde_json::from_str(&json).ok()
        });

        Ok((attack_id, attack, geolocation))
    })?;

    let mut events = Vec::new();

    for row_result in rows {
        let (attack_id, attack, geolocation) = row_result?;

        // Fetch fingerprints
        let fingerprints = get_fingerprints_for_attack(conn, attack_id)?;

        // Fetch Cloudflare metadata
        let cloudflare = get_cloudflare_metadata_for_attack(conn, attack_id)?;

        // Fetch session if exists
        let session = get_attack_session_for_ip(conn, &attack.source_ip)?;

        events.push(EnrichedAttackEvent {
            attack,
            geolocation,
            fingerprints,
            cloudflare,
            session,
        });
    }

    Ok(events)
}

// Helper functions

pub fn get_fingerprints_for_attack(
    conn: &Connection,
    attack_id: i64,
) -> Result<Vec<FingerprintEntry>> {
    let mut stmt = conn.prepare(
        "SELECT fingerprint_type, fingerprint_value, confidence
         FROM fingerprints WHERE attack_id = ?1"
    )?;

    let fingerprints = stmt.query_map([attack_id], |row| {
        let fp_type_str: String = row.get(0)?;
        let fingerprint_type = FingerprintType::from_str(&fp_type_str);

        Ok(FingerprintEntry {
            fingerprint_type,
            value: row.get(1)?,
            confidence: row.get(2)?,
            metadata: None,
        })
    })?
    .collect::<Result<Vec<_>>>()?;

    Ok(fingerprints)
}

fn get_cloudflare_metadata_for_attack(
    conn: &Connection,
    attack_id: i64,
) -> Result<Option<CloudflareMetadata>> {
    let result = conn.query_row(
        "SELECT cf_ray, cf_connecting_ip, cf_ipcountry, cf_visitor,
                cf_threat_score, cf_request_id, cf_colo
         FROM cloudflare_metadata WHERE attack_id = ?1",
        [attack_id],
        |row| {
            Ok(CloudflareMetadata {
                cf_ray: row.get(0)?,
                cf_connecting_ip: row.get(1)?,
                cf_ipcountry: row.get(2)?,
                cf_visitor: row.get(3)?,
                cf_threat_score: row.get(4)?,
                cf_request_id: row.get(5)?,
                cf_colo: row.get(6)?,
            })
        },
    );

    match result {
        Ok(cf) => Ok(Some(cf)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

fn get_attack_session_for_ip(
    conn: &Connection,
    ip: &str,
) -> Result<Option<AttackSession>> {
    let mut stmt = conn.prepare(
        "SELECT id, session_hash, source_ip, first_seen, last_seen,
                attack_count, protocol_count, protocols_used, fingerprints,
                aggregate_threat_level, threat_escalation, persistence_score,
                attack_ids, geolocation
         FROM attack_sessions WHERE source_ip = ?1
         ORDER BY last_seen DESC LIMIT 1"
    )?;

    let result = stmt.query_row([ip], |row| {
        let protocols_json: String = row.get(7)?;
        let fingerprints_json: String = row.get(8)?;
        let attack_ids_json: String = row.get(12)?;

        Ok(AttackSession {
            id: Some(row.get(0)?),
            session_hash: row.get(1)?,
            source_ip: row.get(2)?,
            first_seen: row.get(3)?,
            last_seen: row.get(4)?,
            attack_count: row.get(5)?,
            protocol_count: row.get(6)?,
            protocols_used: serde_json::from_str(&protocols_json).unwrap_or_default(),
            fingerprints: serde_json::from_str(&fingerprints_json).unwrap_or_default(),
            aggregate_threat_level: row.get(9)?,
            threat_escalation: row.get(10)?,
            persistence_score: row.get(11)?,
            attack_ids: serde_json::from_str(&attack_ids_json).unwrap_or_default(),
            geolocation: row.get(13)?,
        })
    });

    match result {
        Ok(session) => Ok(Some(session)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}
