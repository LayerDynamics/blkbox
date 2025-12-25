// Session correlation module for tracking attackers across attacks

use crate::storage::models::AttackSession;
use crate::ffi::types::AttackEvent;
use std::collections::HashMap;
use md5;
use serde::{Serialize, Deserialize};

#[cfg(test)]
use chrono::Utc;

/// Session correlation coordinator
/// Tracks attackers across multiple attacks and protocols
pub struct SessionCorrelator {
    db: std::sync::Arc<std::sync::Mutex<crate::storage::Database>>,
}

impl SessionCorrelator {
    /// Create a new session correlator
    pub fn new(db: std::sync::Arc<std::sync::Mutex<crate::storage::Database>>) -> Self {
        Self { db }
    }

    /// Process an attack event and correlate it with existing sessions
    /// Returns the session hash for this attack
    pub fn correlate_attack(&self, event: &AttackEvent, attack_id: i64, fingerprints: &HashMap<String, String>) -> Result<String, Box<dyn std::error::Error>> {
        // Generate session hash
        let session_hash = generate_session_hash(&event.source_ip, fingerprints);

        // Try to find existing session
        let db = self.db.lock().unwrap();
        let mut session = match db.find_session_by_hash(&session_hash)? {
            Some(existing) => existing,
            None => {
                // Create new session
                AttackSession {
                    id: None,
                    session_hash: session_hash.clone(),
                    source_ip: event.source_ip.clone(),
                    first_seen: event.timestamp.clone(),
                    last_seen: event.timestamp.clone(),
                    attack_count: 0,
                    protocol_count: 0,
                    protocols_used: Vec::new(),
                    fingerprints: HashMap::new(),
                    aggregate_threat_level: 0,
                    threat_escalation: false,
                    persistence_score: 0,
                    attack_ids: Vec::new(),
                    geolocation: None,
                }
            }
        };

        // Update session with new attack
        update_session_with_attack(&mut session, event, attack_id, fingerprints);

        // Persist updated session
        db.upsert_attack_session(&session)?;

        Ok(session_hash)
    }

    /// Get session statistics for an IP address
    pub fn get_ip_sessions(&self, ip: &str) -> Result<Vec<AttackSession>, Box<dyn std::error::Error>> {
        let db = self.db.lock().unwrap();
        Ok(db.find_sessions_by_ip(ip)?)
    }

    /// Calculate threat score for a session
    pub fn calculate_session_threat(&self, session_hash: &str) -> Result<u8, Box<dyn std::error::Error>> {
        let db = self.db.lock().unwrap();
        let session = db.find_session_by_hash(session_hash)?
            .ok_or("Session not found")?;

        Ok(session.aggregate_threat_level)
    }

    /// Create a SessionIdentifier for tracking an attack
    pub fn create_session_identifier(&self, ip: &str, fingerprints: HashMap<String, String>) -> SessionIdentifier {
        SessionIdentifier::new(ip.to_string(), fingerprints)
    }

    /// Get SessionIdentifier for an existing session hash
    pub fn get_session_identifier(&self, session_hash: &str) -> Result<Option<SessionIdentifier>, Box<dyn std::error::Error>> {
        let db = self.db.lock().unwrap();
        if let Some(session) = db.find_session_by_hash(session_hash)? {
            Ok(Some(SessionIdentifier {
                session_hash: session.session_hash,
                source_ip: session.source_ip,
                fingerprints: session.fingerprints,
            }))
        } else {
            Ok(None)
        }
    }
}

/// Generate a deterministic session hash from IP and fingerprints
/// This allows us to identify the same attacker across attacks
fn generate_session_hash(ip: &str, fingerprints: &HashMap<String, String>) -> String {
    let mut hash_input = format!("ip:{}", ip);

    // Add fingerprints in sorted order for determinism
    let mut fp_keys: Vec<_> = fingerprints.keys().collect();
    fp_keys.sort();

    for key in fp_keys {
        if let Some(value) = fingerprints.get(key) {
            hash_input.push_str(&format!("|{}:{}", key, value));
        }
    }

    // Generate MD5 hash
    let digest = md5::compute(hash_input.as_bytes());
    format!("{:x}", digest)
}

/// Update session with new attack information
fn update_session_with_attack(
    session: &mut AttackSession,
    event: &AttackEvent,
    attack_id: i64,
    fingerprints: &HashMap<String, String>,
) {
    // Update timestamps
    session.last_seen = event.timestamp.clone();

    // Increment attack count
    session.attack_count += 1;

    // Add attack ID
    session.attack_ids.push(attack_id);

    // Track protocol usage
    let protocol = event.service_type.as_str();
    if !session.protocols_used.contains(&protocol.to_string()) {
        session.protocols_used.push(protocol.to_string());
        session.protocol_count = session.protocols_used.len() as u32;
    }

    // Merge fingerprints
    for (key, value) in fingerprints {
        session.fingerprints.insert(key.clone(), value.clone());
    }

    // Calculate aggregate threat level
    session.aggregate_threat_level = calculate_aggregate_threat(session, event);

    // Detect threat escalation
    session.threat_escalation = detect_threat_escalation(session, event);

    // Calculate persistence score
    session.persistence_score = calculate_persistence_score(session);
}

/// Calculate aggregate threat level for a session
/// Takes into account all attacks in the session
fn calculate_aggregate_threat(session: &AttackSession, current_event: &AttackEvent) -> u8 {
    let mut threat = current_event.threat_level;

    // Multiple attacks from same IP: +2
    if session.attack_count > 1 {
        threat += 2;
    }

    // Multiple protocols attacked: +3
    if session.protocol_count > 1 {
        threat += 3;
    }

    // High attack frequency: +2
    if session.attack_count > 10 {
        threat += 2;
    }

    // Anonymous proxy/VPN detection would add +3 (from geolocation)
    // This would be checked in a more complete implementation

    threat.min(10)
}

/// Detect if attacker is escalating their attacks
/// Returns true if recent attacks are more severe than earlier ones
fn detect_threat_escalation(session: &AttackSession, current_event: &AttackEvent) -> bool {
    // If this is the first or second attack, no escalation yet
    if session.attack_count < 2 {
        return false;
    }

    // Check if current threat level is significantly higher than baseline
    // In a full implementation, we'd track individual threat levels
    // For now, use a simple heuristic
    current_event.threat_level > 7 && session.attack_count > 3
}

/// Calculate persistence score (0-100) based on attack patterns
/// Higher score = more persistent attacker
fn calculate_persistence_score(session: &AttackSession) -> u8 {
    let mut score = 0u8;

    // Base score from attack count (up to 40 points)
    score += (session.attack_count.min(20) * 2) as u8;

    // Protocol diversity (up to 30 points)
    score += (session.protocol_count.min(6) * 5) as u8;

    // Time span persistence (up to 30 points)
    // Parse timestamps and calculate duration
    if let (Ok(first), Ok(last)) = (
        chrono::DateTime::parse_from_rfc3339(&session.first_seen),
        chrono::DateTime::parse_from_rfc3339(&session.last_seen),
    ) {
        let duration = last.signed_duration_since(first);
        let hours = duration.num_hours();

        // Score based on how long attacker has been active
        if hours >= 24 {
            score += 30;
        } else if hours >= 12 {
            score += 20;
        } else if hours >= 6 {
            score += 15;
        } else if hours >= 1 {
            score += 10;
        } else if hours > 0 {
            score += 5;
        }
    }

    score.min(100)
}

/// Session identifier for correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionIdentifier {
    pub session_hash: String,
    pub source_ip: String,
    pub fingerprints: HashMap<String, String>,
}

impl SessionIdentifier {
    /// Create a new session identifier
    pub fn new(source_ip: String, fingerprints: HashMap<String, String>) -> Self {
        let session_hash = generate_session_hash(&source_ip, &fingerprints);
        Self {
            session_hash,
            source_ip,
            fingerprints,
        }
    }

    /// Get the session hash
    pub fn hash(&self) -> &str {
        &self.session_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_hash_generation() {
        let mut fingerprints = HashMap::new();
        fingerprints.insert("ja3".to_string(), "abc123".to_string());
        fingerprints.insert("hassh".to_string(), "def456".to_string());

        let hash1 = generate_session_hash("1.2.3.4", &fingerprints);
        let hash2 = generate_session_hash("1.2.3.4", &fingerprints);
        let hash3 = generate_session_hash("5.6.7.8", &fingerprints);

        // Same IP and fingerprints should produce same hash
        assert_eq!(hash1, hash2);

        // Different IP should produce different hash
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_persistence_score_calculation() {
        let session = AttackSession {
            id: None,
            session_hash: "test".to_string(),
            source_ip: "1.2.3.4".to_string(),
            first_seen: "2025-01-01T00:00:00Z".to_string(),
            last_seen: "2025-01-02T00:00:00Z".to_string(), // 24 hours later
            attack_count: 15,
            protocol_count: 3,
            protocols_used: vec!["HTTP".to_string(), "SSH".to_string(), "FTP".to_string()],
            fingerprints: HashMap::new(),
            aggregate_threat_level: 0,
            threat_escalation: false,
            persistence_score: 0,
            attack_ids: Vec::new(),
            geolocation: None,
        };

        let score = calculate_persistence_score(&session);

        // Should have:
        // - Attack count: 15 attacks = 30 points
        // - Protocol diversity: 3 protocols = 15 points
        // - Time span: >24 hours = 30 points
        // Total: 75 points
        assert_eq!(score, 75);
    }

    #[test]
    fn test_aggregate_threat_calculation() {
        let session = AttackSession {
            id: None,
            session_hash: "test".to_string(),
            source_ip: "1.2.3.4".to_string(),
            first_seen: Utc::now().to_rfc3339(),
            last_seen: Utc::now().to_rfc3339(),
            attack_count: 5,
            protocol_count: 2,
            protocols_used: vec!["HTTP".to_string(), "SSH".to_string()],
            fingerprints: HashMap::new(),
            aggregate_threat_level: 0,
            threat_escalation: false,
            persistence_score: 0,
            attack_ids: Vec::new(),
            geolocation: None,
        };

        let event = AttackEvent {
            timestamp: Utc::now().to_rfc3339(),
            source_ip: "1.2.3.4".to_string(),
            source_port: 12345,
            service_type: crate::ffi::types::ServiceType::HTTP,
            service_id: 1,
            user_agent: None,
            payload: String::new(),
            threat_level: 5,
            fingerprint: None,
            cf_metadata: None,
            attack_id: Some(uuid::Uuid::new_v4().to_string()),
        };

        let threat = calculate_aggregate_threat(&session, &event);

        // Should have:
        // - Base threat: 5
        // - Multiple attacks: +2
        // - Multiple protocols: +3
        // Total: 10 (capped)
        assert_eq!(threat, 10);
    }
}
