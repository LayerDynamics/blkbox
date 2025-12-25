// FFI-safe type definitions for BlkBox

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::ffi::CStr;
use std::os::raw::c_char;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono;
use tokio::sync::mpsc;
use uuid;
use crate::tracking::{GeoIpReader, GeolocationCache};
use std::time::Duration;

/// Main runtime structure for BlkBox honeypot system
/// This is the core FFI structure that maintains state across the FFI boundary
pub struct BlkBoxRuntime {
    /// Tokio async runtime for handling async operations
    pub tokio_runtime: tokio::runtime::Runtime,

    /// Map of service ID to service handles
    /// Each honeypot service gets a unique ID
    pub services: Arc<Mutex<HashMap<u32, ServiceHandle>>>,

    /// Database connection pool
    pub db: Arc<Mutex<crate::storage::Database>>,

    /// Queue of attack events waiting to be read by Deno
    pub event_queue: Arc<Mutex<VecDeque<AttackEvent>>>,

    /// Next service ID to assign
    pub next_service_id: Arc<Mutex<u32>>,

    /// Event sender channel for honeypots to send attack events
    pub event_sender: mpsc::UnboundedSender<AttackEvent>,

    /// Event receiver (kept in runtime to receive events from honeypots)
    event_receiver: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<AttackEvent>>>,

    /// GeoIP reader for IP geolocation lookups
    pub geoip_reader: Arc<GeoIpReader>,

    /// Geolocation cache with 1-hour TTL
    pub geo_cache: Arc<GeolocationCache>,

    /// Session correlator for tracking attackers across attacks
    pub session_correlator: Arc<crate::tracking::SessionCorrelator>,

    /// Fingerprint engine for generating attack fingerprints
    pub fingerprint_engine: Arc<crate::tracking::FingerprintEngine>,

    /// Strikeback service for offensive countermeasures
    pub strikeback_service: Arc<crate::strikeback::StrikebackService>,
}

impl BlkBoxRuntime {
    /// Create a new BlkBox runtime
    pub fn new() -> Result<Self> {
        let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        let db = Arc::new(Mutex::new(crate::storage::Database::new("./blkbox.db")?));

        // Create event channel for honeypots to send events
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        let event_receiver = Arc::new(tokio::sync::Mutex::new(event_receiver));

        // Spawn task to move events from channel to queue
        let event_queue = Arc::new(Mutex::new(VecDeque::new()));
        let queue_clone = Arc::clone(&event_queue);
        let receiver_clone = Arc::clone(&event_receiver);

        tokio_runtime.spawn(async move {
            loop {
                let event = {
                    let mut rx = receiver_clone.lock().await;
                    rx.recv().await
                };

                match event {
                    Some(evt) => {
                        let mut queue = queue_clone.lock().unwrap();
                        queue.push_back(evt);
                    }
                    None => break, // Channel closed
                }
            }
        });

        // Initialize GeoIP reader (MaxMind databases)
        // Look for GeoLite2 databases in common locations
        let geoip_reader = Arc::new(GeoIpReader::new(
            Some("./GeoLite2-City.mmdb"),
            Some("./GeoLite2-ASN.mmdb"),
        ));

        // Initialize geolocation cache with 1-hour TTL
        let geo_cache = Arc::new(GeolocationCache::new(Duration::from_secs(3600)));

        // Initialize session correlator
        let session_correlator = Arc::new(crate::tracking::SessionCorrelator::new(Arc::clone(&db)));

        // Initialize fingerprint engine
        let fingerprint_engine = Arc::new(crate::tracking::FingerprintEngine::new());

        // Initialize strikeback service with default configuration
        let strikeback_config = crate::strikeback::StrikebackConfig::default();

        // Create tokio mutex-wrapped database for strikeback (needs async mutex)
        // StrikebackService uses async mutex for async operations
        let db_for_strikeback = Arc::new(tokio::sync::Mutex::new(
            crate::storage::Database::new("./blkbox.db")?
        ));

        let strikeback_service = Arc::new(crate::strikeback::StrikebackService::new(
            strikeback_config,
            db_for_strikeback
        ));

        Ok(Self {
            tokio_runtime,
            services: Arc::new(Mutex::new(HashMap::new())),
            db,
            event_queue,
            next_service_id: Arc::new(Mutex::new(1)),
            event_sender,
            event_receiver,
            geoip_reader,
            geo_cache,
            session_correlator,
            fingerprint_engine,
            strikeback_service,
        })
    }

    /// Get the next available service ID
    pub fn get_next_service_id(&self) -> u32 {
        let mut id = self.next_service_id.lock().unwrap();
        let current = *id;
        *id += 1;
        current
    }

    /// Add an event to the queue
    pub fn push_event(&self, event: AttackEvent) {
        let mut queue = self.event_queue.lock().unwrap();
        queue.push_back(event);
    }

    /// Get all pending events from the queue
    pub fn drain_events(&self) -> Vec<AttackEvent> {
        let mut queue = self.event_queue.lock().unwrap();
        queue.drain(..).collect()
    }

    /// Get a reference to the event receiver for manual processing
    /// This allows direct access to the channel for custom event handling
    pub fn event_receiver(&self) -> &Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<AttackEvent>>> {
        &self.event_receiver
    }

    /// Check if there are pending events in the receiver channel
    /// Returns the approximate number of events waiting to be processed
    pub fn pending_event_count(&self) -> usize {
        self.event_queue.lock().unwrap().len()
    }

    /// Manually process one event from the receiver into the queue
    /// Returns true if an event was processed, false if channel is empty
    /// This is useful for testing or manual event pipeline control
    pub fn process_one_event(&self) -> bool {
        let receiver = Arc::clone(&self.event_receiver);
        let queue = Arc::clone(&self.event_queue);
        self.tokio_runtime.block_on(async move {
            let mut rx = receiver.lock().await;
            match rx.try_recv() {
                Ok(event) => {
                    drop(rx); // Release lock before queue lock
                    // Push event to the queue
                    let mut q = queue.lock().unwrap();
                    q.push_back(event);
                    true
                }
                Err(_) => false,
            }
        })
    }
}

/// Service types supported by BlkBox
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceType {
    HTTP = 0,
    HTTPS = 1,
    SSH = 2,
    PostgreSQL = 3,
    MySQL = 4,
    MongoDB = 5,
    FTP = 6,
    SFTP = 7,
}

impl ServiceType {
    /// Convert from u8 to ServiceType
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ServiceType::HTTP),
            1 => Some(ServiceType::HTTPS),
            2 => Some(ServiceType::SSH),
            3 => Some(ServiceType::PostgreSQL),
            4 => Some(ServiceType::MySQL),
            5 => Some(ServiceType::MongoDB),
            6 => Some(ServiceType::FTP),
            7 => Some(ServiceType::SFTP),
            _ => None,
        }
    }

    /// Get service name as string
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceType::HTTP => "HTTP",
            ServiceType::HTTPS => "HTTPS",
            ServiceType::SSH => "SSH",
            ServiceType::PostgreSQL => "PostgreSQL",
            ServiceType::MySQL => "MySQL",
            ServiceType::MongoDB => "MongoDB",
            ServiceType::FTP => "FTP",
            ServiceType::SFTP => "SFTP",
        }
    }
}

/// Payload types for strikeback operations
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadType {
    ReverseTCP = 0,
    CommandInjection = 1,
    FileExfiltration = 2,
    LogWiper = 3,
    NetworkScanner = 4,
    BrowserRecon = 5,
    SystemInfo = 6,
    Beacon = 7,
}

impl PayloadType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(PayloadType::ReverseTCP),
            1 => Some(PayloadType::CommandInjection),
            2 => Some(PayloadType::FileExfiltration),
            3 => Some(PayloadType::LogWiper),
            4 => Some(PayloadType::NetworkScanner),
            5 => Some(PayloadType::BrowserRecon),
            6 => Some(PayloadType::SystemInfo),
            7 => Some(PayloadType::Beacon),
            _ => None,
        }
    }

    /// Get payload type name as string
    pub fn as_str(&self) -> &'static str {
        match self {
            PayloadType::ReverseTCP => "ReverseTCP",
            PayloadType::CommandInjection => "CommandInjection",
            PayloadType::FileExfiltration => "FileExfiltration",
            PayloadType::LogWiper => "LogWiper",
            PayloadType::NetworkScanner => "NetworkScanner",
            PayloadType::BrowserRecon => "BrowserRecon",
            PayloadType::SystemInfo => "SystemInfo",
            PayloadType::Beacon => "Beacon",
        }
    }
}

/// Handle to a running honeypot service
pub struct ServiceHandle {
    pub service_id: u32,
    pub service_type: ServiceType,
    pub port: u16,
    pub active: bool,
    /// Shutdown signal sender to stop the honeypot
    pub shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

/// Attack event captured by honeypot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEvent {
    pub timestamp: String,
    pub source_ip: String,
    pub source_port: u16,
    pub service_type: ServiceType,
    pub service_id: u32,
    pub user_agent: Option<String>,
    pub payload: String,
    pub threat_level: u8,
    pub fingerprint: Option<String>,
    pub cf_metadata: Option<std::collections::HashMap<String, String>>,
    pub attack_id: Option<String>,
}

impl AttackEvent {
    /// Create a new attack event with auto-generated UUID
    pub fn new(
        source_ip: String,
        source_port: u16,
        service_type: ServiceType,
        service_id: u32,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            source_ip,
            source_port,
            service_type,
            service_id,
            user_agent: None,
            payload: String::new(),
            threat_level: 0,
            fingerprint: None,
            cf_metadata: None,
            attack_id: Some(uuid::Uuid::new_v4().to_string()),
        }
    }
}

/// FFI helper functions for string conversion
pub mod ffi_helpers {
    use super::*;

    /// Convert C string to Rust String
    /// # Safety
    /// The c_str pointer must be valid and null-terminated
    pub unsafe fn c_str_to_string(c_str: *const c_char) -> Result<String> {
        if c_str.is_null() {
            anyhow::bail!("Null pointer passed as string");
        }

        let c_str = CStr::from_ptr(c_str);
        Ok(c_str.to_string_lossy().into_owned())
    }

    /// Convert Rust String to JSON C string
    /// Returns pointer to heap-allocated string that must be freed
    pub fn string_to_c_str(s: String) -> *mut c_char {
        let c_string = std::ffi::CString::new(s).unwrap_or_else(|_| {
            std::ffi::CString::new("").unwrap()
        });
        c_string.into_raw()
    }

    /// Convert Vec<AttackEvent> to JSON string
    pub fn events_to_json(events: Vec<AttackEvent>) -> String {
        serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_string())
    }

    /// Parse ServiceConfig from JSON string
    pub fn parse_service_config(json: &str) -> Result<ServiceConfig> {
        serde_json::from_str(json)
            .map_err(|e| anyhow::anyhow!("Failed to parse service config: {}", e))
    }
}

/// Service configuration passed from Deno
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub enabled: bool,
    pub custom_responses: Option<HashMap<String, String>>,
    pub banner_grabbing: Option<bool>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            custom_responses: None,
            banner_grabbing: Some(true),
        }
    }
}

/// Cloudflare configuration for API operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareConfig {
    pub api_token: String,
    pub zone_id: String,
    pub account_id: Option<String>,
    pub email: Option<String>,
}

impl CloudflareConfig {
    /// Create from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| anyhow::anyhow!("Failed to parse Cloudflare config: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_type_conversion() {
        assert_eq!(ServiceType::from_u8(0), Some(ServiceType::HTTP));
        assert_eq!(ServiceType::from_u8(2), Some(ServiceType::SSH));
        assert_eq!(ServiceType::from_u8(99), None);
    }

    #[test]
    fn test_attack_event_creation() {
        let event = AttackEvent::new(
            "1.2.3.4".to_string(),
            12345,
            ServiceType::HTTP,
            1,
        );

        assert_eq!(event.source_ip, "1.2.3.4");
        assert_eq!(event.source_port, 12345);
        assert_eq!(event.service_type, ServiceType::HTTP);
    }
}
