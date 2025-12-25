use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Geolocation data structure
/// Stored as JSON in attacks.geolocation field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeolocationData {
    /// IP address that was geolocated
    pub ip: String,

    /// ISO country code (US, CN, RU, etc.)
    pub country_code: Option<String>,

    /// Country name
    pub country_name: Option<String>,

    /// Region/State
    pub region: Option<String>,

    /// City
    pub city: Option<String>,

    /// Latitude
    pub latitude: Option<f64>,

    /// Longitude
    pub longitude: Option<f64>,

    /// Postal/ZIP code
    pub postal_code: Option<String>,

    /// Timezone (IANA format)
    pub timezone: Option<String>,

    /// Autonomous System Number
    pub asn: Option<u32>,

    /// ISP/Organization name
    pub isp: Option<String>,

    /// Organization name
    pub organization: Option<String>,

    /// VPN/Proxy detection
    pub is_anonymous_proxy: bool,

    /// Satellite internet detection
    pub is_satellite_provider: bool,

    /// Data source (MaxMind, Cloudflare, IPGeolocation, etc.)
    pub source: GeoSource,
}

impl Default for GeolocationData {
    fn default() -> Self {
        Self {
            ip: String::new(),
            country_code: None,
            country_name: None,
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            postal_code: None,
            timezone: None,
            asn: None,
            isp: None,
            organization: None,
            is_anonymous_proxy: false,
            is_satellite_provider: false,
            source: GeoSource::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GeoSource {
    Cloudflare,      // From CF headers (fastest, most reliable when available)
    MaxMind,         // From GeoLite2 database
    Hybrid,          // Both Cloudflare and MaxMind data
    Direct,          // Direct socket connection (no proxy)
    Unknown,         // Fallback
}

/// Individual fingerprint entry
/// Stored in fingerprints table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintEntry {
    /// Type of fingerprint
    pub fingerprint_type: FingerprintType,

    /// Fingerprint value/hash
    pub value: String,

    /// Confidence score (0.0 to 1.0)
    pub confidence: f32,

    /// Additional metadata (JSON)
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FingerprintType {
    /// JA3 TLS fingerprint
    JA3,

    /// JA3S server fingerprint
    JA3S,

    /// Hassh SSH client fingerprint
    Hassh,

    /// Hassh server fingerprint
    HasshServer,

    /// User-Agent fingerprint
    UserAgent,

    /// Browser canvas fingerprint
    Canvas,

    /// HTTP header order
    HeaderOrder,

    /// Tool detection (nmap, sqlmap, etc.)
    ToolDetection,

    /// Custom fingerprint type
    Custom(String),
}

impl FingerprintType {
    pub fn as_str(&self) -> String {
        match self {
            Self::JA3 => "ja3".to_string(),
            Self::JA3S => "ja3s".to_string(),
            Self::Hassh => "hassh".to_string(),
            Self::HasshServer => "hassh_server".to_string(),
            Self::UserAgent => "user_agent".to_string(),
            Self::Canvas => "canvas".to_string(),
            Self::HeaderOrder => "header_order".to_string(),
            Self::ToolDetection => "tool_detection".to_string(),
            Self::Custom(s) => s.clone(),
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "ja3" => Self::JA3,
            "ja3s" => Self::JA3S,
            "hassh" => Self::Hassh,
            "hassh_server" => Self::HasshServer,
            "user_agent" => Self::UserAgent,
            "canvas" => Self::Canvas,
            "header_order" => Self::HeaderOrder,
            "tool_detection" => Self::ToolDetection,
            other => Self::Custom(other.to_string()),
        }
    }
}

/// Session data tracking
/// Stored in sessions table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// Unique session identifier
    pub session_token: String,

    /// Initial attack ID that started the session
    pub attack_id: i64,

    /// Session start time
    pub started_at: String,

    /// Session end time (if ended)
    pub ended_at: Option<String>,

    /// Commands executed (for SSH, FTP)
    pub commands: Vec<String>,

    /// Queries executed (for database honeypots)
    pub queries: Vec<String>,

    /// Files accessed
    pub files_accessed: Vec<String>,

    /// Additional session metadata
    pub metadata: Option<serde_json::Value>,
}

/// Cloudflare metadata
/// Stored in cloudflare_metadata table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareMetadata {
    /// CF-Ray header (unique request ID)
    pub cf_ray: Option<String>,

    /// CF-Connecting-IP (real client IP)
    pub cf_connecting_ip: Option<String>,

    /// CF-IPCountry (ISO country code)
    pub cf_ipcountry: Option<String>,

    /// CF-Visitor (http/https)
    pub cf_visitor: Option<String>,

    /// CF-Threat-Score (0-100)
    pub cf_threat_score: Option<i32>,

    /// CF-Request-ID
    pub cf_request_id: Option<String>,

    /// CF-Colo (datacenter location)
    pub cf_colo: Option<String>,
}

impl CloudflareMetadata {
    /// Extract from HTTP headers
    pub fn from_headers(headers: &axum::http::HeaderMap) -> Option<Self> {
        // Only return Some if at least one CF header is present
        if headers.get("cf-ray").is_none()
            && headers.get("cf-connecting-ip").is_none()
            && headers.get("cf-ipcountry").is_none() {
            return None;
        }

        Some(Self {
            cf_ray: headers
                .get("cf-ray")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            cf_connecting_ip: headers
                .get("cf-connecting-ip")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            cf_ipcountry: headers
                .get("cf-ipcountry")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            cf_visitor: headers
                .get("cf-visitor")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            cf_threat_score: headers
                .get("cf-threat-score")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok()),
            cf_request_id: headers
                .get("cf-request-id")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            cf_colo: headers
                .get("cf-colo")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
        })
    }

    /// Convert from HashMap (as stored in AttackEvent)
    pub fn from_hashmap(map: &std::collections::HashMap<String, String>) -> Option<Self> {
        // Only return Some if at least one CF field is present
        if map.is_empty() {
            return None;
        }

        Some(Self {
            cf_ray: map.get("cf_ray").cloned(),
            cf_connecting_ip: map.get("cf_connecting_ip").cloned(),
            cf_ipcountry: map.get("cf_ipcountry").cloned(),
            cf_visitor: map.get("cf_visitor").cloned(),
            cf_threat_score: map.get("cf_threat_score")
                .and_then(|s| s.parse().ok()),
            cf_request_id: map.get("cf_request_id").cloned(),
            cf_colo: map.get("cf_colo").cloned(),
        })
    }
}

/// Attack session for correlation
/// Stored in attack_sessions table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSession {
    /// Database ID
    pub id: Option<i64>,

    /// Session hash (deterministic ID)
    pub session_hash: String,

    /// Source IP address
    pub source_ip: String,

    /// First attack timestamp
    pub first_seen: String,

    /// Last attack timestamp
    pub last_seen: String,

    /// Number of attacks in session
    pub attack_count: u32,

    /// Number of unique protocols used
    pub protocol_count: u32,

    /// Protocols used (JSON array)
    pub protocols_used: Vec<String>,

    /// Fingerprints (JSON map)
    pub fingerprints: HashMap<String, String>,

    /// Aggregate threat level (0-100)
    pub aggregate_threat_level: u8,

    /// Threat escalation detected
    pub threat_escalation: bool,

    /// Persistence score (0-100)
    pub persistence_score: u8,

    /// Linked attack IDs (JSON array)
    pub attack_ids: Vec<i64>,

    /// Geolocation from first attack
    pub geolocation: Option<String>,
}

/// Enriched attack event with all tracking data
/// Used for complex queries and analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedAttackEvent {
    /// Base attack event
    pub attack: crate::ffi::types::AttackEvent,

    /// Geolocation data
    pub geolocation: Option<GeolocationData>,

    /// Multiple fingerprints
    pub fingerprints: Vec<FingerprintEntry>,

    /// Cloudflare metadata
    pub cloudflare: Option<CloudflareMetadata>,

    /// Associated session
    pub session: Option<AttackSession>,
}
