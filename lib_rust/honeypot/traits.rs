// Trait definitions for honeypot services

use async_trait::async_trait;
use anyhow::Result;
use crate::ffi::types::{AttackEvent, ServiceType};
use std::net::SocketAddr;

/// Core trait that all honeypot services must implement
/// This provides a consistent interface for starting, stopping, and managing honeypots
#[async_trait]
pub trait HoneypotService: Send + Sync {
    /// Get the service type this honeypot implements
    fn service_type(&self) -> ServiceType;

    /// Get the port this honeypot is listening on
    fn port(&self) -> u16;

    /// Start the honeypot service
    /// This should bind to the port and begin accepting connections
    async fn start(&mut self) -> Result<()>;

    /// Stop the honeypot service
    /// This should gracefully shut down all connections
    async fn stop(&mut self) -> Result<()>;

    /// Check if the honeypot is currently running
    fn is_running(&self) -> bool;

    /// Get statistics about this honeypot
    fn stats(&self) -> HoneypotStats;
}

/// Statistics tracked by each honeypot service
#[derive(Debug, Clone, Default)]
pub struct HoneypotStats {
    /// Total number of connections received
    pub total_connections: u64,

    /// Number of currently active connections
    pub active_connections: u32,

    /// Total number of attack events generated
    pub total_attacks: u64,

    /// Number of unique source IPs
    pub unique_ips: u32,

    /// Service uptime in seconds
    pub uptime_seconds: u64,
}

/// Context information passed to request handlers
/// Contains everything needed to process and log an attack
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Client's socket address (IP + port)
    pub client_addr: SocketAddr,

    /// Service ID assigned by BlkBox runtime
    pub service_id: u32,

    /// Service type (HTTP, SSH, etc.)
    pub service_type: ServiceType,

    /// User-Agent header (HTTP) or client banner (SSH/FTP)
    pub user_agent: Option<String>,

    /// Full request payload (headers, body, commands)
    pub payload: String,

    /// Detected threat level (0-10)
    pub threat_level: u8,

    /// Optional fingerprint (JA3, SSH key, etc.)
    pub fingerprint: Option<String>,

    /// Cloudflare metadata (if behind Cloudflare)
    pub cf_metadata: Option<std::collections::HashMap<String, String>>,
}

impl RequestContext {
    /// Convert this context into an AttackEvent for storage
    pub fn to_attack_event(&self) -> AttackEvent {
        AttackEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            source_ip: self.client_addr.ip().to_string(),
            source_port: self.client_addr.port(),
            service_type: self.service_type,
            service_id: self.service_id,
            user_agent: self.user_agent.clone(),
            payload: self.payload.clone(),
            threat_level: self.threat_level,
            fingerprint: self.fingerprint.clone(),
            cf_metadata: self.cf_metadata.clone(),
            attack_id: None,
        }
    }
}

/// Fingerprinting utilities for detecting attack tools
pub mod fingerprint {
    /// Detect if the User-Agent looks like a scanner/attack tool
    pub fn is_suspicious_user_agent(user_agent: &str) -> bool {
        let suspicious_keywords = [
            "nmap", "sqlmap", "nikto", "masscan", "zgrab",
            "shodan", "censys", "nuclei", "metasploit",
            "burp", "zap", "acunetix", "nessus", "qualys",
            "python-requests", "curl", "wget", "gobuster",
            "dirbuster", "wfuzz", "ffuf", "feroxbuster",
        ];

        let lower_ua = user_agent.to_lowercase();
        suspicious_keywords.iter().any(|keyword| lower_ua.contains(keyword))
    }

    /// Calculate threat level based on various indicators
    pub fn calculate_threat_level(
        user_agent: &Option<String>,
        path: &str,
        method: &str,
    ) -> u8 {
        let mut threat_level = 0u8;

        // Suspicious user agent: +3
        if let Some(ua) = user_agent {
            if is_suspicious_user_agent(ua) {
                threat_level += 3;
            }
        }

        // No user agent at all: +2
        if user_agent.is_none() {
            threat_level += 2;
        }

        // Common attack paths: +4
        let attack_paths = [
            "/admin", "/.git", "/.env", "/wp-admin", "/phpmyadmin",
            "/config", "/backup", "/db", "/.aws", "/api/v1",
            "/login", "/console", "/dashboard", "/shell",
        ];
        if attack_paths.iter().any(|p| path.contains(p)) {
            threat_level += 4;
        }

        // SQL injection attempts: +5
        if path.contains("'") || path.contains("--") || path.contains("union") {
            threat_level += 5;
        }

        // Directory traversal: +5
        if path.contains("../") || path.contains("..\\") {
            threat_level += 5;
        }

        // Non-GET methods on common paths: +2
        if method != "GET" && method != "HEAD" {
            threat_level += 2;
        }

        // Cap at 10
        threat_level.min(10)
    }
}
