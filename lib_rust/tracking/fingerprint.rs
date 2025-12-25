// Fingerprinting module for attacker identification
// Implements JA3 TLS, Hassh SSH, and behavioral fingerprinting

use crate::storage::models::{FingerprintEntry, FingerprintType};
use md5;
use std::collections::HashMap;

/// Main fingerprint engine coordinator
pub struct FingerprintEngine {
    // Configuration options
    enable_ja3: bool,
    enable_hassh: bool,
    enable_behavioral: bool,
}

impl FingerprintEngine {
    /// Create a new fingerprint engine with all fingerprinting enabled
    pub fn new() -> Self {
        Self {
            enable_ja3: true,
            enable_hassh: true,
            enable_behavioral: true,
        }
    }

    /// Create a fingerprint engine with custom configuration
    pub fn with_config(enable_ja3: bool, enable_hassh: bool, enable_behavioral: bool) -> Self {
        Self {
            enable_ja3,
            enable_hassh,
            enable_behavioral,
        }
    }

    /// Generate all applicable fingerprints for a connection
    pub fn fingerprint_connection(
        &self,
        connection_type: &str,
        data: &HashMap<String, String>,
    ) -> Vec<FingerprintEntry> {
        let mut fingerprints = Vec::new();

        match connection_type {
            "ssh" => {
                if self.enable_hassh {
                    if let Some(fp) = self.fingerprint_ssh(data) {
                        fingerprints.push(fp);
                    }
                }
            }
            "tls" | "https" => {
                if self.enable_ja3 {
                    if let Some(fp) = self.fingerprint_tls(data) {
                        fingerprints.push(fp);
                    }
                }
            }
            "http" => {
                if self.enable_behavioral {
                    if let Some(fp) = self.fingerprint_http_behavioral(data) {
                        fingerprints.push(fp);
                    }
                }
            }
            _ => {}
        }

        fingerprints
    }

    /// Generate SSH Hassh fingerprint
    fn fingerprint_ssh(&self, data: &HashMap<String, String>) -> Option<FingerprintEntry> {
        // Extract SSH algorithm lists from data
        let kex = data.get("kex_algorithms")?;
        let encryption = data.get("encryption_algorithms")?;
        let mac = data.get("mac_algorithms")?;
        let compression = data.get("compression_algorithms")?;

        let hassh = compute_hassh(kex, encryption, mac, compression);

        Some(FingerprintEntry {
            fingerprint_type: FingerprintType::Hassh,
            value: hassh,
            confidence: 0.9,
            metadata: Some(serde_json::to_string(&data).ok()?),
        })
    }

    /// Generate TLS JA3 fingerprint
    fn fingerprint_tls(&self, data: &HashMap<String, String>) -> Option<FingerprintEntry> {
        // Extract TLS ClientHello parameters
        let version = data.get("tls_version")?;
        let ciphers = data.get("cipher_suites")?;
        let extensions = data.get("extensions")?;
        let curves = data.get("elliptic_curves").map(|s| s.as_str()).unwrap_or("");
        let point_formats = data.get("ec_point_formats").map(|s| s.as_str()).unwrap_or("");

        let ja3 = compute_ja3(version, ciphers, extensions, curves, point_formats);

        Some(FingerprintEntry {
            fingerprint_type: FingerprintType::JA3,
            value: ja3,
            confidence: 0.85,
            metadata: Some(serde_json::to_string(&data).ok()?),
        })
    }

    /// Generate behavioral fingerprint from HTTP patterns
    fn fingerprint_http_behavioral(&self, data: &HashMap<String, String>) -> Option<FingerprintEntry> {
        // Extract HTTP behavioral characteristics
        let user_agent = data.get("user_agent")?;
        let header_order = data.get("header_order").map(|s| s.as_str()).unwrap_or("");
        let accept_headers = data.get("accept").map(|s| s.as_str()).unwrap_or("");

        // Create a behavioral fingerprint from these elements
        let fp_string = format!(
            "ua:{}|ho:{}|ac:{}",
            user_agent, header_order, accept_headers
        );

        let digest = md5::compute(fp_string.as_bytes());
        let fingerprint_hash = format!("{:x}", digest);

        Some(FingerprintEntry {
            fingerprint_type: FingerprintType::HeaderOrder,
            value: fingerprint_hash,
            confidence: 0.7,
            metadata: Some(serde_json::to_string(&data).ok()?),
        })
    }
}

/// Compute Hassh fingerprint for SSH connections
/// Hassh format: md5(kex;encryption;mac;compression)
pub fn compute_hassh(
    kex_algorithms: &str,
    encryption_algorithms: &str,
    mac_algorithms: &str,
    compression_algorithms: &str,
) -> String {
    let hassh_string = format!(
        "{};{};{};{}",
        kex_algorithms, encryption_algorithms, mac_algorithms, compression_algorithms
    );

    let digest = md5::compute(hassh_string.as_bytes());
    format!("{:x}", digest)
}

/// Compute JA3 fingerprint for TLS connections
/// JA3 format: md5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
pub fn compute_ja3(
    tls_version: &str,
    cipher_suites: &str,
    extensions: &str,
    elliptic_curves: &str,
    ec_point_formats: &str,
) -> String {
    let ja3_string = format!(
        "{},{},{},{},{}",
        tls_version, cipher_suites, extensions, elliptic_curves, ec_point_formats
    );

    let digest = md5::compute(ja3_string.as_bytes());
    format!("{:x}", digest)
}

/// Extract SSH algorithms from SSH banner/exchange
/// Parses SSH_MSG_KEXINIT packet (message type 20) to extract algorithm lists
pub fn extract_ssh_algorithms(ssh_data: &[u8]) -> Option<SshAlgorithms> {
    // SSH_MSG_KEXINIT packet structure:
    // - uint32: packet_length (first 4 bytes)
    // - byte: padding_length
    // - byte: SSH_MSG_KEXINIT (20)
    // - byte[16]: cookie (random)
    // - name-list: kex_algorithms
    // - name-list: server_host_key_algorithms
    // - name-list: encryption_algorithms_client_to_server
    // - name-list: encryption_algorithms_server_to_client
    // - name-list: mac_algorithms_client_to_server
    // - name-list: mac_algorithms_server_to_client
    // - name-list: compression_algorithms_client_to_server
    // - name-list: compression_algorithms_server_to_client
    // - name-list: languages_client_to_server
    // - name-list: languages_server_to_client
    // - boolean: first_kex_packet_follows
    // - uint32: 0 (reserved)

    if ssh_data.len() < 22 {
        return None; // Not enough data for minimum packet
    }

    let mut pos = 0;

    // Read packet length (uint32, big-endian)
    if pos + 4 > ssh_data.len() {
        return None;
    }
    let packet_length = u32::from_be_bytes([
        ssh_data[pos],
        ssh_data[pos + 1],
        ssh_data[pos + 2],
        ssh_data[pos + 3],
    ]) as usize;
    pos += 4;

    // Verify we have enough data for the full packet
    if pos + packet_length > ssh_data.len() {
        return None;
    }

    // Read padding length (used for packet validation)
    if pos >= ssh_data.len() {
        return None;
    }
    let _padding_length = ssh_data[pos] as usize;
    pos += 1;

    // Read message type (should be 20 for SSH_MSG_KEXINIT)
    if pos >= ssh_data.len() {
        return None;
    }
    let msg_type = ssh_data[pos];
    if msg_type != 20 {
        return None; // Not a KEXINIT packet
    }
    pos += 1;

    // Skip cookie (16 bytes)
    if pos + 16 > ssh_data.len() {
        return None;
    }
    pos += 16;

    // Helper function to read name-list
    fn read_name_list(data: &[u8], pos: &mut usize) -> Option<Vec<String>> {
        if *pos + 4 > data.len() {
            return None;
        }

        // Read length of name-list (uint32, big-endian)
        let length = u32::from_be_bytes([
            data[*pos],
            data[*pos + 1],
            data[*pos + 2],
            data[*pos + 3],
        ]) as usize;
        *pos += 4;

        if *pos + length > data.len() {
            return None;
        }

        // Read name-list string
        let name_list_str = String::from_utf8_lossy(&data[*pos..*pos + length]);
        *pos += length;

        // Parse comma-separated list
        let names: Vec<String> = name_list_str
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        Some(names)
    }

    // Read algorithm name-lists in order
    let kex_algorithms = read_name_list(ssh_data, &mut pos)?;
    let server_host_key_algorithms = read_name_list(ssh_data, &mut pos)?;
    let encryption_algorithms_client_to_server = read_name_list(ssh_data, &mut pos)?;
    let encryption_algorithms_server_to_client = read_name_list(ssh_data, &mut pos)?;
    let mac_algorithms_client_to_server = read_name_list(ssh_data, &mut pos)?;
    let mac_algorithms_server_to_client = read_name_list(ssh_data, &mut pos)?;
    let compression_algorithms_client_to_server = read_name_list(ssh_data, &mut pos)?;
    let compression_algorithms_server_to_client = read_name_list(ssh_data, &mut pos)?;

    // We've successfully parsed the KEXINIT packet
    Some(SshAlgorithms {
        kex_algorithms,
        server_host_key_algorithms,
        encryption_algorithms_client_to_server,
        encryption_algorithms_server_to_client,
        mac_algorithms_client_to_server,
        mac_algorithms_server_to_client,
        compression_algorithms_client_to_server,
        compression_algorithms_server_to_client,
    })
}

/// SSH algorithm lists extracted from key exchange
#[derive(Debug, Clone)]
pub struct SshAlgorithms {
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_client_to_server: Vec<String>,
    pub encryption_algorithms_server_to_client: Vec<String>,
    pub mac_algorithms_client_to_server: Vec<String>,
    pub mac_algorithms_server_to_client: Vec<String>,
    pub compression_algorithms_client_to_server: Vec<String>,
    pub compression_algorithms_server_to_client: Vec<String>,
}

impl SshAlgorithms {
    /// Convert to Hassh string (client fingerprint)
    /// Uses client-to-server algorithms
    pub fn to_hassh_string(&self) -> String {
        format!(
            "{};{};{};{}",
            self.kex_algorithms.join(","),
            self.encryption_algorithms_client_to_server.join(","),
            self.mac_algorithms_client_to_server.join(","),
            self.compression_algorithms_client_to_server.join(",")
        )
    }

    /// Convert to Hassh Server string (server fingerprint)
    /// Uses server-to-client algorithms
    pub fn to_hassh_server_string(&self) -> String {
        format!(
            "{};{};{};{}",
            self.kex_algorithms.join(","),
            self.encryption_algorithms_server_to_client.join(","),
            self.mac_algorithms_server_to_client.join(","),
            self.compression_algorithms_server_to_client.join(",")
        )
    }

    /// Compute Hassh fingerprint from these algorithms (client fingerprint)
    pub fn compute_hassh(&self) -> String {
        let hassh_string = self.to_hassh_string();
        let digest = md5::compute(hassh_string.as_bytes());
        format!("{:x}", digest)
    }

    /// Compute Hassh Server fingerprint (server fingerprint)
    pub fn compute_hassh_server(&self) -> String {
        let hassh_server_string = self.to_hassh_server_string();
        let digest = md5::compute(hassh_server_string.as_bytes());
        format!("{:x}", digest)
    }

    /// Get a summary of all algorithms for analysis
    pub fn summary(&self) -> String {
        format!(
            "KEX: {}, Host Keys: {}, Enc C2S: {}, Enc S2C: {}, MAC C2S: {}, MAC S2C: {}, Comp C2S: {}, Comp S2C: {}",
            self.kex_algorithms.join(","),
            self.server_host_key_algorithms.join(","),
            self.encryption_algorithms_client_to_server.join(","),
            self.encryption_algorithms_server_to_client.join(","),
            self.mac_algorithms_client_to_server.join(","),
            self.mac_algorithms_server_to_client.join(","),
            self.compression_algorithms_client_to_server.join(","),
            self.compression_algorithms_server_to_client.join(",")
        )
    }
}

/// Tool detection from User-Agent and behavioral patterns
pub fn detect_attack_tool(user_agent: &str, path_pattern: &str) -> Option<String> {
    let ua_lower = user_agent.to_lowercase();

    // Common attack tools
    let tools = [
        ("nmap", "Nmap"),
        ("masscan", "Masscan"),
        ("zmap", "ZMap"),
        ("zgrab", "ZGrab"),
        ("sqlmap", "SQLMap"),
        ("nikto", "Nikto"),
        ("metasploit", "Metasploit"),
        ("burp", "Burp Suite"),
        ("zaproxy", "OWASP ZAP"),
        ("acunetix", "Acunetix"),
        ("nessus", "Nessus"),
        ("qualys", "Qualys"),
        ("nuclei", "Nuclei"),
        ("gobuster", "Gobuster"),
        ("dirbuster", "DirBuster"),
        ("wfuzz", "WFuzz"),
        ("ffuf", "ffuf"),
        ("feroxbuster", "Feroxbuster"),
        ("shodan", "Shodan"),
        ("censys", "Censys"),
        ("python-requests", "Python Requests (Script)"),
        ("curl", "cURL (Manual/Script)"),
        ("wget", "Wget (Script)"),
    ];

    for (signature, tool_name) in &tools {
        if ua_lower.contains(signature) {
            return Some(tool_name.to_string());
        }
    }

    // Path-based detection
    if path_pattern.contains("/.git/") {
        return Some("Git Directory Scanner".to_string());
    }
    if path_pattern.contains("/wp-") {
        return Some("WordPress Scanner".to_string());
    }
    if path_pattern.contains("/phpmyadmin") {
        return Some("phpMyAdmin Scanner".to_string());
    }

    None
}

/// Create tool detection fingerprint
pub fn fingerprint_tool_detection(user_agent: &str, path: &str) -> Option<FingerprintEntry> {
    let tool = detect_attack_tool(user_agent, path)?;

    let mut metadata = HashMap::new();
    metadata.insert("tool".to_string(), tool.clone());
    metadata.insert("user_agent".to_string(), user_agent.to_string());
    metadata.insert("path".to_string(), path.to_string());

    Some(FingerprintEntry {
        fingerprint_type: FingerprintType::ToolDetection,
        value: tool,
        confidence: 0.95,
        metadata: serde_json::to_string(&metadata).ok(),
    })
}

/// Fingerprint result type alias
pub type Fingerprint = FingerprintEntry;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hassh_computation() {
        let kex = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256";
        let enc = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr";
        let mac = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com";
        let comp = "none,zlib@openssh.com";

        let hassh = compute_hassh(kex, enc, mac, comp);

        // Hassh should be a 32-character hex string (MD5)
        assert_eq!(hassh.len(), 32);
        assert!(hassh.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_ja3_computation() {
        let version = "771"; // TLS 1.2
        let ciphers = "49195,49199,52393,52392,49196,49200,49162,49161,49171,49172";
        let extensions = "0,10,11,13,23,35";
        let curves = "23,24,25";
        let formats = "0";

        let ja3 = compute_ja3(version, ciphers, extensions, curves, formats);

        // JA3 should be a 32-character hex string (MD5)
        assert_eq!(ja3.len(), 32);
        assert!(ja3.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_tool_detection() {
        assert_eq!(
            detect_attack_tool("Mozilla/5.0 (compatible; Nmap Scripting Engine)", "/"),
            Some("Nmap".to_string())
        );

        assert_eq!(
            detect_attack_tool("sqlmap/1.0", "/admin/login.php"),
            Some("SQLMap".to_string())
        );

        assert_eq!(
            detect_attack_tool("python-requests/2.28.0", "/api/users"),
            Some("Python Requests (Script)".to_string())
        );

        assert_eq!(
            detect_attack_tool("Mozilla/5.0", "/.git/config"),
            Some("Git Directory Scanner".to_string())
        );

        assert_eq!(
            detect_attack_tool("Mozilla/5.0", "/wp-admin/"),
            Some("WordPress Scanner".to_string())
        );
    }

    #[test]
    fn test_fingerprint_engine() {
        let engine = FingerprintEngine::new();

        // Test SSH fingerprinting
        let mut ssh_data = HashMap::new();
        ssh_data.insert("kex_algorithms".to_string(), "diffie-hellman-group14-sha1".to_string());
        ssh_data.insert("encryption_algorithms".to_string(), "aes128-ctr".to_string());
        ssh_data.insert("mac_algorithms".to_string(), "hmac-sha1".to_string());
        ssh_data.insert("compression_algorithms".to_string(), "none".to_string());

        let fingerprints = engine.fingerprint_connection("ssh", &ssh_data);
        assert_eq!(fingerprints.len(), 1);
        assert!(matches!(fingerprints[0].fingerprint_type, FingerprintType::Hassh));

        // Test TLS fingerprinting
        let mut tls_data = HashMap::new();
        tls_data.insert("tls_version".to_string(), "771".to_string());
        tls_data.insert("cipher_suites".to_string(), "49195,49199".to_string());
        tls_data.insert("extensions".to_string(), "0,10,11".to_string());

        let fingerprints = engine.fingerprint_connection("tls", &tls_data);
        assert_eq!(fingerprints.len(), 1);
        assert!(matches!(fingerprints[0].fingerprint_type, FingerprintType::JA3));
    }

    #[test]
    fn test_ssh_algorithms_hassh() {
        let algorithms = SshAlgorithms {
            kex_algorithms: vec!["curve25519-sha256".to_string()],
            server_host_key_algorithms: vec!["ssh-rsa".to_string()],
            encryption_algorithms_client_to_server: vec!["aes128-ctr".to_string()],
            encryption_algorithms_server_to_client: vec!["aes128-ctr".to_string()],
            mac_algorithms_client_to_server: vec!["hmac-sha2-256".to_string()],
            mac_algorithms_server_to_client: vec!["hmac-sha2-256".to_string()],
            compression_algorithms_client_to_server: vec!["none".to_string()],
            compression_algorithms_server_to_client: vec!["none".to_string()],
        };

        let hassh = algorithms.compute_hassh();
        assert_eq!(hassh.len(), 32);
    }
}
