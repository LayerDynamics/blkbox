/**
 * Threat Assessment and Decision Engine
 *
 * Implements the core decision logic for strike-back deployments including:
 * - Threat scoring algorithm (0-10 scale)
 * - Safeguard enforcement (whitelisting, geofencing, etc.)
 * - Deployment decision tree
 * - Audit logging
 */

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::net::IpAddr;
use ipnetwork::IpNetwork;

use crate::ffi::types::{AttackEvent, PayloadType, ServiceType};
use crate::tracking::{AttackSession, GeolocationData};
use super::StrikebackConfig;

/**
 * Threat assessment results
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssessment {
    /// Final threat score (0-10)
    pub score: f32,

    /// Score breakdown
    pub breakdown: ScoreBreakdown,

    /// Recommended payload type
    pub recommended_payload: Option<PayloadType>,
}

/**
 * Score breakdown for transparency
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub base_threat_level: f32,
    pub repeat_attacker_bonus: f32,
    pub escalation_bonus: f32,
    pub multi_protocol_bonus: f32,
    pub persistence_bonus: f32,
    pub tool_detection_bonus: f32,
    pub cloudflare_bonus: f32,
}

/**
 * Safeguard check results
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeguardResults {
    pub passed: bool,
    pub summary: String,
    pub checks: Vec<SafeguardCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeguardCheck {
    pub name: String,
    pub passed: bool,
    pub reason: Option<String>,
}

/**
 * Deployment decision
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentDecision {
    pub decision: Decision,
    pub threat_assessment: ThreatAssessment,
    pub safeguard_results: SafeguardResults,
    pub payload_type: Option<PayloadType>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Decision {
    Approve,  // Auto-deploy
    Queue,    // Queue for manual approval
    Deny,     // Reject deployment
}

/**
 * Threat Assessor - Calculates threat scores
 */
pub struct ThreatAssessor {
    config: Arc<StrikebackConfig>,
}

impl ThreatAssessor {
    pub fn new(config: Arc<StrikebackConfig>) -> Self {
        Self { config }
    }

    /**
     * Calculate threat score for an attack event
     *
     * Score components (0-10 scale):
     * - Base threat level: 0-3 points (from honeypot)
     * - Repeat attacker: +1-2 points
     * - Threat escalation: +2 points
     * - Multi-protocol: +1 point
     * - Persistence: +1 point
     * - Tool detection: +1 point
     * - Cloudflare threat score: +0-2 points
     */
    pub fn assess(
        &self,
        event: &AttackEvent,
        session: Option<&AttackSession>,
        _geolocation: Option<&GeolocationData>,
    ) -> ThreatAssessment {
        let mut breakdown = ScoreBreakdown {
            base_threat_level: event.threat_level as f32,
            repeat_attacker_bonus: 0.0,
            escalation_bonus: 0.0,
            multi_protocol_bonus: 0.0,
            persistence_bonus: 0.0,
            tool_detection_bonus: 0.0,
            cloudflare_bonus: 0.0,
        };

        // Session-based bonuses
        if let Some(sess) = session {
            // Repeat attacker bonus
            if sess.attack_count > 1 {
                breakdown.repeat_attacker_bonus += 1.0;
            }
            if sess.attack_count > 5 {
                breakdown.repeat_attacker_bonus += 1.0;
            }

            // Threat escalation
            if sess.threat_escalation {
                breakdown.escalation_bonus = 2.0;
            }

            // Multi-protocol attacks
            if sess.protocol_count > 1 {
                breakdown.multi_protocol_bonus = 1.0;
            }

            // Persistence score (0-100 scale)
            if sess.persistence_score > 70 {
                breakdown.persistence_bonus = 1.0;
            }
        }

        // Tool detection
        if let Some(fp) = &event.fingerprint {
            if self.is_attack_tool(fp) {
                breakdown.tool_detection_bonus = 1.0;
            }
        }

        // Cloudflare threat score
        if let Some(cf_metadata) = &event.cf_metadata {
            if let Some(threat_score_str) = cf_metadata.get("cf_threat_score") {
                if let Ok(threat_score) = threat_score_str.parse::<u32>() {
                    if threat_score > 75 {
                        breakdown.cloudflare_bonus = (threat_score as f32 / 50.0).min(2.0);
                    }
                }
            }
        }

        // Calculate total score
        let score = (breakdown.base_threat_level
            + breakdown.repeat_attacker_bonus
            + breakdown.escalation_bonus
            + breakdown.multi_protocol_bonus
            + breakdown.persistence_bonus
            + breakdown.tool_detection_bonus
            + breakdown.cloudflare_bonus)
            .min(10.0);

        // Recommend payload type based on score
        let recommended_payload = self.recommend_payload(event, score, session);

        ThreatAssessment {
            score,
            breakdown,
            recommended_payload,
        }
    }

    /**
     * Detect if fingerprint indicates attack tool
     */
    fn is_attack_tool(&self, fingerprint: &str) -> bool {
        let tools = [
            "nmap", "masscan", "zmap", "sqlmap", "nikto", "metasploit",
            "burp", "nuclei", "acunetix", "nessus", "openvas",
        ];

        let fp_lower = fingerprint.to_lowercase();
        tools.iter().any(|tool| fp_lower.contains(tool))
    }

    /**
     * Recommend payload type based on attack characteristics
     */
    fn recommend_payload(
        &self,
        event: &AttackEvent,
        score: f32,
        session: Option<&AttackSession>,
    ) -> Option<PayloadType> {
        // Critical threats (score >= 9.0)
        if score >= 9.0 {
            return match event.service_type {
                ServiceType::SSH => Some(PayloadType::ReverseTCP),
                ServiceType::PostgreSQL | ServiceType::MySQL | ServiceType::MongoDB => {
                    if event.payload.contains("UNION") || event.payload.contains("SELECT") {
                        Some(PayloadType::CommandInjection)
                    } else {
                        Some(PayloadType::SystemInfo)
                    }
                }
                _ => Some(PayloadType::SystemInfo),
            };
        }

        // High threats (score >= 8.0)
        if score >= 8.0 {
            if let Some(sess) = session {
                if sess.protocol_count > 1 {
                    return Some(PayloadType::NetworkScanner);
                }
            }
            return Some(PayloadType::BrowserRecon);
        }

        // Medium threats (score >= 7.5)
        if score >= self.config.threat_threshold {
            if let Some(sess) = session {
                if sess.attack_count > 3 {
                    return Some(PayloadType::Beacon);
                }
            }
            return Some(PayloadType::SystemInfo);
        }

        None
    }
}

/**
 * Safeguard Engine - Enforces deployment safeguards
 */
pub struct SafeguardEngine {
    config: Arc<StrikebackConfig>,
}

impl SafeguardEngine {
    pub fn new(config: Arc<StrikebackConfig>) -> Self {
        Self { config }
    }

    /**
     * Run all safeguard checks
     *
     * ALL checks must pass for deployment to be approved
     */
    pub fn check(
        &self,
        event: &AttackEvent,
        session: Option<&AttackSession>,
        geolocation: Option<&GeolocationData>,
        payload_type: PayloadType,
    ) -> SafeguardResults {
        let mut checks = Vec::new();

        // Check 1: Whitelisting
        checks.push(self.check_whitelist(event));

        // Check 2: Legitimate scanner detection
        checks.push(self.check_legitimate_scanner(event));

        // Check 3: Geofencing
        checks.push(self.check_geofencing(geolocation));

        // Check 4: Minimum attack threshold
        checks.push(self.check_minimum_threshold(session));

        // Check 5: Payload capability restrictions
        checks.push(self.check_payload_allowed(payload_type));

        // Overall result
        let passed = checks.iter().all(|check| check.passed);
        let summary = if passed {
            "All safeguard checks passed".to_string()
        } else {
            format!(
                "Failed checks: {}",
                checks
                    .iter()
                    .filter(|c| !c.passed)
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };

        SafeguardResults {
            passed,
            summary,
            checks,
        }
    }

    /**
     * Check if IP is whitelisted
     */
    fn check_whitelist(&self, event: &AttackEvent) -> SafeguardCheck {
        let ip_str = &event.source_ip;

        // Check direct IP whitelist
        if self.config.whitelist_ips.contains(ip_str) {
            return SafeguardCheck {
                name: "Whitelist".to_string(),
                passed: false,
                reason: Some(format!("IP {} is whitelisted", ip_str)),
            };
        }

        // Check CIDR whitelist
        if let Ok(ip_addr) = ip_str.parse::<IpAddr>() {
            for cidr_str in &self.config.whitelist_cidrs {
                if let Ok(network) = cidr_str.parse::<IpNetwork>() {
                    if network.contains(ip_addr) {
                        return SafeguardCheck {
                            name: "Whitelist".to_string(),
                            passed: false,
                            reason: Some(format!("IP {} is in whitelisted CIDR {}", ip_str, cidr_str)),
                        };
                    }
                }
            }
        }

        SafeguardCheck {
            name: "Whitelist".to_string(),
            passed: true,
            reason: None,
        }
    }

    /**
     * Check if this is a legitimate security scanner
     */
    fn check_legitimate_scanner(&self, event: &AttackEvent) -> SafeguardCheck {
        let legitimate_scanners = [
            "Shodan", "Censys", "Googlebot", "BingBot",
            "SecurityScanner", "Qualys", "Nessus", "Rapid7",
        ];

        if let Some(ua) = &event.user_agent {
            for scanner in &legitimate_scanners {
                if ua.contains(scanner) {
                    return SafeguardCheck {
                        name: "Legitimate Scanner".to_string(),
                        passed: false,
                        reason: Some(format!("Detected legitimate scanner: {}", scanner)),
                    };
                }
            }
        }

        SafeguardCheck {
            name: "Legitimate Scanner".to_string(),
            passed: true,
            reason: None,
        }
    }

    /**
     * Check geofencing restrictions
     */
    fn check_geofencing(&self, geolocation: Option<&GeolocationData>) -> SafeguardCheck {
        if let Some(geo) = geolocation {
            if let Some(country_code) = &geo.country_code {
                // Check prohibited countries
                if self.config.prohibited_countries.contains(country_code) {
                    return SafeguardCheck {
                        name: "Geofencing".to_string(),
                        passed: false,
                        reason: Some(format!("Country {} is prohibited", country_code)),
                    };
                }

                // If allowlist is specified, check it
                if !self.config.allowed_countries.is_empty()
                    && !self.config.allowed_countries.contains(country_code)
                {
                    return SafeguardCheck {
                        name: "Geofencing".to_string(),
                        passed: false,
                        reason: Some(format!("Country {} is not in allowed list", country_code)),
                    };
                }
            }
        }

        SafeguardCheck {
            name: "Geofencing".to_string(),
            passed: true,
            reason: None,
        }
    }

    /**
     * Check minimum attack threshold
     */
    fn check_minimum_threshold(&self, session: Option<&AttackSession>) -> SafeguardCheck {
        if let Some(sess) = session {
            if sess.attack_count < self.config.min_attack_count {
                return SafeguardCheck {
                    name: "Minimum Threshold".to_string(),
                    passed: false,
                    reason: Some(format!(
                        "Attack count {} is below minimum {}",
                        sess.attack_count, self.config.min_attack_count
                    )),
                };
            }
        } else {
            return SafeguardCheck {
                name: "Minimum Threshold".to_string(),
                passed: false,
                reason: Some("No session data available".to_string()),
            };
        }

        SafeguardCheck {
            name: "Minimum Threshold".to_string(),
            passed: true,
            reason: None,
        }
    }

    /**
     * Check if payload type is allowed - all payloads allowed
     */
    fn check_payload_allowed(&self, _payload_type: PayloadType) -> SafeguardCheck {
        // All payload types are allowed without restriction
        SafeguardCheck {
            name: "Payload Restriction".to_string(),
            passed: true,
            reason: None,
        }
    }
}

/**
 * Decision Engine - Combines threat assessment and safeguards
 */
pub struct DecisionEngine {
    config: Arc<StrikebackConfig>,
    threat_assessor: ThreatAssessor,
    safeguard_engine: SafeguardEngine,
}

impl DecisionEngine {
    pub fn new(config: Arc<StrikebackConfig>) -> Self {
        let threat_assessor = ThreatAssessor::new(Arc::clone(&config));
        let safeguard_engine = SafeguardEngine::new(Arc::clone(&config));

        Self {
            config,
            threat_assessor,
            safeguard_engine,
        }
    }

    /**
     * Make deployment decision for an attack event
     */
    pub async fn assess(
        &self,
        event: &AttackEvent,
        session: Option<&AttackSession>,
        geolocation: Option<&GeolocationData>,
    ) -> Result<DeploymentDecision> {
        // Step 1: Assess threat
        let threat_assessment = self.threat_assessor.assess(event, session, geolocation);

        // Step 2: Check if threat score meets threshold
        if threat_assessment.score < self.config.threat_threshold {
            let score = threat_assessment.score;
            let threshold = self.config.threat_threshold;
            return Ok(DeploymentDecision {
                decision: Decision::Deny,
                threat_assessment,
                safeguard_results: SafeguardResults {
                    passed: false,
                    summary: "Threat score below threshold".to_string(),
                    checks: vec![],
                },
                payload_type: None,
                reason: format!(
                    "Threat score {:.2} is below threshold {:.2}",
                    score, threshold
                ),
            });
        }

        // Step 3: Get recommended payload
        let payload_type = threat_assessment
            .recommended_payload
            .ok_or_else(|| anyhow!("No payload type recommended"))?;

        // Step 4: Run safeguard checks
        let safeguard_results = self.safeguard_engine.check(event, session, geolocation, payload_type);

        if !safeguard_results.passed {
            let summary = safeguard_results.summary.clone();
            return Ok(DeploymentDecision {
                decision: Decision::Deny,
                threat_assessment,
                safeguard_results,
                payload_type: Some(payload_type),
                reason: format!("Safeguard check failed: {}", summary),
            });
        }

        // Step 5: Check if system is enabled
        if !self.config.enabled {
            return Ok(DeploymentDecision {
                decision: Decision::Deny,
                threat_assessment,
                safeguard_results,
                payload_type: Some(payload_type),
                reason: "Strike-back system is disabled".to_string(),
            });
        }

        // Step 6: Check dry-run mode
        if self.config.dry_run {
            return Ok(DeploymentDecision {
                decision: Decision::Queue,
                threat_assessment,
                safeguard_results,
                payload_type: Some(payload_type),
                reason: "Dry-run mode: would approve deployment".to_string(),
            });
        }

        // Step 7: Check if manual approval required
        if self.config.require_approval || self.requires_manual_approval(payload_type, threat_assessment.score) {
            return Ok(DeploymentDecision {
                decision: Decision::Queue,
                threat_assessment,
                safeguard_results,
                payload_type: Some(payload_type),
                reason: "Manual approval required".to_string(),
            });
        }

        // Step 8: Check auto-trigger
        if !self.config.auto_trigger {
            return Ok(DeploymentDecision {
                decision: Decision::Queue,
                threat_assessment,
                safeguard_results,
                payload_type: Some(payload_type),
                reason: "Auto-trigger disabled, queued for manual approval".to_string(),
            });
        }

        // All checks passed - approve auto-deployment
        let score = threat_assessment.score;
        Ok(DeploymentDecision {
            decision: Decision::Approve,
            threat_assessment,
            safeguard_results,
            payload_type: Some(payload_type),
            reason: format!(
                "Auto-approved: threat score {:.2}, all safeguards passed",
                score
            ),
        })
    }

    /**
     * Check if payload type requires manual approval
     */
    fn requires_manual_approval(&self, payload_type: PayloadType, score: f32) -> bool {
        // High-risk payloads always require approval
        matches!(
            payload_type,
            PayloadType::ReverseTCP | PayloadType::CommandInjection | PayloadType::FileExfiltration
        ) || score >= 9.5
    }
}
