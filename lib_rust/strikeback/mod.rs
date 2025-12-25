/**
 * BlkBox Strike-Back Capabilities Module
 *
 * Implements offensive/defensive capabilities for deploying reconnaissance
 * payloads to confirmed attackers. This module provides:
 *
 * 1. Threat Assessment - Scoring and decision engine
 * 2. Safeguard Enforcement - Whitelisting, geofencing
 * 3. Payload Management - Generation and lifecycle tracking
 * 4. C2 Infrastructure - Command and control for payload callbacks
 * 5. Delivery Mechanisms - Protocol-specific payload delivery
 *
 * ## Configuration
 *
 * This module is designed for security research and defensive operations.
 * Features include:
 * - Multiple safeguard checks
 * - Comprehensive audit logging
 * - Flexible payload types
 *
 * Default configuration uses dry-run mode and manual approval.
 */

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod decision;
pub mod payload;
pub mod c2;
pub mod delivery;

pub use decision::{ThreatAssessor, SafeguardEngine, DecisionEngine, SafeguardResults, DeploymentDecision};
pub use payload::{PayloadGenerator, PayloadConfig, GeneratedPayload};
pub use c2::{C2Server, C2Callback, IntelligenceData};
pub use delivery::{DeliveryEngine, DeliveryMethod, DeliveryResult};

use crate::ffi::types::{AttackEvent, PayloadType, ServiceType};
use crate::storage::Database;
use crate::tracking::{AttackSession, GeolocationData};

/**
 * Strikeback configuration
 */
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StrikebackConfig {
    /// Enable strike-back capabilities
    pub enabled: bool,

    /// Automatically trigger payloads (vs. require manual approval)
    pub auto_trigger: bool,

    /// Minimum threat score to trigger (0-10 scale)
    pub threat_threshold: f32,

    /// Minimum number of attacks before triggering
    pub min_attack_count: u32,

    /// Dry-run mode (simulate but don't deploy)
    pub dry_run: bool,

    /// Require manual approval for all deployments
    pub require_approval: bool,

    /// Allowed payload types
    pub allowed_payloads: Vec<String>,

    /// Prohibited payload types
    pub prohibited_payloads: Vec<String>,

    /// Whitelisted IP addresses (never target)
    pub whitelist_ips: Vec<String>,

    /// Whitelisted CIDR ranges
    pub whitelist_cidrs: Vec<String>,

    /// Allowed countries (ISO codes)
    pub allowed_countries: Vec<String>,

    /// Prohibited countries (ISO codes)
    pub prohibited_countries: Vec<String>,

    /// Payload expiration in hours
    pub payload_expiration_hours: u32,

    /// Maximum callbacks per payload
    pub max_callbacks_per_payload: u32,

    /// C2 server port
    pub c2_port: u16,

    /// Use TLS for C2
    pub c2_use_tls: bool,

    /// Legal compliance flags
    pub legal: LegalConfig,
}

impl Default for StrikebackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_trigger: false,
            threat_threshold: 7.5,
            min_attack_count: 3,
            dry_run: true,
            require_approval: true,
            allowed_payloads: vec![
                "system_info".to_string(),
                "browser_recon".to_string(),
                "network_scanner".to_string(),
                "beacon".to_string(),
            ],
            prohibited_payloads: vec!["log_wiper".to_string()],
            whitelist_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
            whitelist_cidrs: vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
            ],
            allowed_countries: vec![],
            prohibited_countries: vec![
                "US".to_string(),
                "CA".to_string(),
                "GB".to_string(),
                "AU".to_string(),
                "NZ".to_string(),
                "DE".to_string(),
                "FR".to_string(),
            ],
            payload_expiration_hours: 24,
            max_callbacks_per_payload: 100,
            c2_port: 8443,
            c2_use_tls: true,
            legal: LegalConfig::default(),
        }
    }
}

/**
 * Legal compliance configuration
 */
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LegalConfig {
    pub counsel_consulted: bool,
    pub jurisdiction: String,
    pub warning_banner_enabled: bool,
}

impl Default for LegalConfig {
    fn default() -> Self {
        Self {
            counsel_consulted: false,
            jurisdiction: "US".to_string(),
            warning_banner_enabled: true,
        }
    }
}

/**
 * Main Strikeback Service
 *
 * Coordinates all strike-back operations including threat assessment,
 * payload generation, deployment, and C2 management.
 */
pub struct StrikebackService {
    config: Arc<StrikebackConfig>,
    decision_engine: DecisionEngine,
    payload_generator: PayloadGenerator,
    delivery_engine: DeliveryEngine,
    c2_server: Option<C2Server>,
    db: Arc<tokio::sync::Mutex<Database>>,
}

impl StrikebackService {
    /**
     * Create a new StrikebackService
     */
    pub fn new(config: StrikebackConfig, db: Arc<tokio::sync::Mutex<Database>>) -> Self {
        let config_arc = Arc::new(config);

        let decision_engine = DecisionEngine::new(Arc::clone(&config_arc));
        let payload_generator = PayloadGenerator::new(Arc::clone(&config_arc));
        let delivery_engine = DeliveryEngine::new(Arc::clone(&config_arc));

        Self {
            config: config_arc,
            decision_engine,
            payload_generator,
            delivery_engine,
            c2_server: None,
            db,
        }
    }

    /**
     * Start the C2 server
     */
    pub async fn start_c2_server(&mut self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let c2_server = C2Server::new(
            self.config.c2_port,
            self.config.c2_use_tls,
            Arc::clone(&self.db),
        );

        c2_server.start().await?;
        self.c2_server = Some(c2_server);

        Ok(())
    }

    /**
     * Assess whether to deploy a payload for an attack event
     */
    pub async fn assess_attack(
        &self,
        event: &AttackEvent,
        session: Option<&AttackSession>,
        geolocation: Option<&GeolocationData>,
    ) -> Result<DeploymentDecision> {
        self.decision_engine.assess(event, session, geolocation).await
    }

    /**
     * Generate and deploy a payload
     */
    pub async fn deploy_payload(
        &self,
        event: &AttackEvent,
        payload_type: PayloadType,
        delivery_method: DeliveryMethod,
    ) -> Result<GeneratedPayload> {
        // Generate payload
        let mut payload = self.payload_generator.generate(event, payload_type).await?;

        // Adapt payload for the specific protocol
        let delivery_result = self.delivery_engine.adapt(
            &payload.code,
            event,
            &payload.payload_id,
        )?;

        // Update payload with adapted code
        payload.code = delivery_result.adapted_payload.clone();
        payload.delivery_method = format!("{:?}", delivery_result.method);

        // Store in database
        self.store_payload(&payload).await?;

        // Deliver payload using the specified delivery method
        self.delivery_engine.deliver(&payload, delivery_method).await?;

        // Log deployment with delivery instructions
        self.log_deployment(event, &payload).await?;

        Ok(payload)
    }

    /**
     * Store payload in database
     */
    async fn store_payload(&self, payload: &GeneratedPayload) -> Result<()> {
        let db = self.db.lock().await;

        db.execute_raw(
            r#"
            INSERT INTO payloads (
                payload_id, payload_type, payload_code, target_ip,
                created_at, expires_at, status, delivery_method,
                delivery_count, c2_callback_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            rusqlite::params![
                payload.payload_id,
                format!("{:?}", payload.payload_type),
                payload.code,
                payload.target_ip,
                payload.created_at,
                payload.expires_at,
                "ready",
                payload.delivery_method,
                0,
                0,
            ],
        )?;

        Ok(())
    }

    /**
     * Log deployment to audit table
     */
    async fn log_deployment(&self, event: &AttackEvent, payload: &GeneratedPayload) -> Result<()> {
        let db = self.db.lock().await;

        db.execute_raw(
            r#"
            INSERT INTO strikeback_audit (
                timestamp, event_type, attack_id, payload_id,
                attacker_ip, threat_score, decision, payload_type,
                approval_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            rusqlite::params![
                chrono::Utc::now().to_rfc3339(),
                "deployment",
                event.attack_id,
                payload.payload_id,
                event.source_ip,
                0.0, // Would come from decision
                "approve",
                format!("{:?}", payload.payload_type),
                if self.config.require_approval { "manual" } else { "auto" },
            ],
        )?;

        Ok(())
    }

    /**
     * Get active payloads
     */
    pub async fn get_active_payloads(&self) -> Result<Vec<GeneratedPayload>> {
        let db = self.db.lock().await;

        let payloads = db.with_connection(|conn| {
            let mut stmt = conn.prepare(
                "SELECT payload_id, payload_type, payload_code, target_ip,
                        created_at, expires_at, delivery_method
                 FROM payloads
                 WHERE status = 'active' OR status = 'ready'"
            )?;

            let payloads = stmt.query_map([], |row| {
                let payload_type_str: String = row.get(1)?;
                let payload_type = match payload_type_str.as_str() {
                    "SystemInfo" => PayloadType::SystemInfo,
                    "BrowserRecon" => PayloadType::BrowserRecon,
                    "NetworkScanner" => PayloadType::NetworkScanner,
                    "Beacon" => PayloadType::Beacon,
                    "ReverseTCP" => PayloadType::ReverseTCP,
                    "CommandInjection" => PayloadType::CommandInjection,
                    "FileExfiltration" => PayloadType::FileExfiltration,
                    _ => PayloadType::SystemInfo,
                };

                Ok(GeneratedPayload {
                    payload_id: row.get(0)?,
                    payload_type,
                    code: row.get(2)?,
                    target_ip: row.get(3)?,
                    created_at: row.get(4)?,
                    expires_at: row.get(5)?,
                    delivery_method: row.get(6)?,
                    c2_url: String::new(),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

            Ok(payloads)
        })?;

        Ok(payloads)
    }

    /**
     * Terminate a payload
     */
    pub async fn terminate_payload(&self, payload_id: &str) -> Result<()> {
        let db = self.db.lock().await;

        db.execute_raw(
            "UPDATE payloads SET status = 'terminated' WHERE payload_id = ?",
            rusqlite::params![payload_id],
        )?;

        // Log termination
        db.execute_raw(
            r#"
            INSERT INTO strikeback_audit (
                timestamp, event_type, payload_id, decision
            ) VALUES (?, ?, ?, ?)
            "#,
            rusqlite::params![
                chrono::Utc::now().to_rfc3339(),
                "termination",
                payload_id,
                "terminate",
            ],
        )?;

        Ok(())
    }

    /**
     * Cleanup expired payloads
     */
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let db = self.db.lock().await;

        let now = chrono::Utc::now().to_rfc3339();

        let count = db.execute_raw(
            "UPDATE payloads SET status = 'expired' WHERE expires_at < ? AND status != 'expired'",
            rusqlite::params![now],
        )?;

        Ok(count)
    }
}
