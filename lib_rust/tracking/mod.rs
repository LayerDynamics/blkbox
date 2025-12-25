// Tracking module for attacker identification and correlation

pub mod geolocation;
pub mod fingerprint;
pub mod session;

// Re-export storage models for convenience
pub use crate::storage::models::{GeolocationData, AttackSession};

pub use geolocation::{GeoIpReader, GeolocationCache, extract_real_ip, extract_cloudflare_metadata, lookup_geolocation};
pub use fingerprint::{FingerprintEngine, Fingerprint};
pub use session::{SessionCorrelator, SessionIdentifier};
