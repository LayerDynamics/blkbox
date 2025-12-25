// FTP Session Management
// Tracks session state, threat scoring, and client fingerprinting

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;
use super::data_channel::DataChannelManager;

/// FTP Connection States
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpState {
    /// TCP connection established, waiting for USER
    Connected,
    /// USER command received, waiting for PASS
    UserProvided,
    /// PASS command received, user logged in
    LoggedIn,
    /// RNFR command received, waiting for RNTO
    Renaming,
    /// Connection closed
    Disconnected,
}

/// FTP Session
/// Tracks per-connection state and activity for threat analysis
pub struct FtpSession {
    /// Current connection state
    pub state: FtpState,

    /// Client socket address
    pub client_addr: SocketAddr,

    /// Unique session identifier
    pub session_id: String,

    // Authentication
    pub username: Option<String>,
    pub password: Option<String>,
    pub auth_attempts: u32,

    // Navigation
    pub current_dir: PathBuf,

    // Transfer settings
    pub binary_mode: bool,
    pub data_channel: DataChannelManager,

    // File operations
    pub rename_from: Option<String>,

    // Session tracking
    pub command_count: u32,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub files_accessed: Vec<String>,
    pub commands: Vec<String>,

    // Threat indicators
    pub uploaded_executables: bool,
    pub downloaded_sensitive: bool,
    pub directory_traversal_attempted: bool,

    // Timing
    pub session_start: Instant,
    pub last_command: Instant,
}

impl FtpSession {
    /// Create a new FTP session
    pub fn new(client_addr: SocketAddr) -> Self {
        Self {
            state: FtpState::Connected,
            client_addr,
            session_id: Uuid::new_v4().to_string(),
            username: None,
            password: None,
            auth_attempts: 0,
            current_dir: PathBuf::from("/"),
            binary_mode: true, // Default to binary mode
            data_channel: DataChannelManager::new(),
            rename_from: None,
            command_count: 0,
            bytes_uploaded: 0,
            bytes_downloaded: 0,
            files_accessed: Vec::new(),
            commands: Vec::new(),
            uploaded_executables: false,
            downloaded_sensitive: false,
            directory_traversal_attempted: false,
            session_start: Instant::now(),
            last_command: Instant::now(),
        }
    }

    /// Add a command to the history
    pub fn add_command(&mut self, command: &str) {
        self.commands.push(command.to_string());
        self.command_count += 1;
        self.last_command = Instant::now();

        // Check for directory traversal
        if command.contains("..") {
            self.directory_traversal_attempted = true;
        }
    }

    /// Mark a file as accessed
    pub fn access_file(&mut self, path: &str) {
        self.files_accessed.push(path.to_string());

        // Check for sensitive files
        let sensitive_paths = ["/etc/passwd", "/etc/shadow", "/.env", "/backup/", "/.ssh/"];
        if sensitive_paths.iter().any(|s| path.contains(s)) {
            self.downloaded_sensitive = true;
        }
    }

    /// Calculate threat level for this session (0-10)
    pub fn calculate_threat_level(&self) -> u8 {
        let mut threat = 0u8;

        // Base FTP connection
        threat += 2;

        // Anonymous login
        if self.username.as_deref() == Some("anonymous") {
            threat += 1;
        }

        // Admin/root username
        if matches!(self.username.as_deref(), Some("admin" | "root" | "administrator")) {
            threat += 3;
        }

        // Multiple authentication attempts
        if self.auth_attempts > 3 {
            threat += 2;
        }

        // Sensitive paths accessed
        let sensitive = ["/etc/shadow", "/etc/passwd", "/.ssh/", "/.env", "/backup/"];
        if self.files_accessed.iter().any(|f| {
            sensitive.iter().any(|s| f.contains(s))
        }) {
            threat += 4;
        }

        // Uploaded executables
        if self.uploaded_executables {
            threat += 5;
        }

        // Downloaded sensitive files
        if self.downloaded_sensitive {
            threat += 3;
        }

        // High command rate (scanner)
        let duration_secs = self.session_start.elapsed().as_secs_f32();
        if duration_secs > 0.0 {
            let rate = self.command_count as f32 / duration_secs;
            if rate > 5.0 {
                threat += 2;
            }
        }

        // Directory traversal
        if self.directory_traversal_attempted {
            threat += 4;
        }

        // Dangerous commands
        let dangerous = ["SITE EXEC", "SITE CHMOD", "DELE /etc/", "RMD /"];
        if self.commands.iter().any(|cmd| {
            dangerous.iter().any(|d| cmd.to_uppercase().contains(d))
        }) {
            threat += 3;
        }

        // Cap at 10
        threat.min(10)
    }

    /// Fingerprint the FTP client
    pub fn fingerprint_client(&self) -> Option<String> {
        if self.commands.is_empty() {
            return None;
        }

        // FileZilla: CLNT command
        if self.commands.iter().any(|c| c.to_uppercase().starts_with("CLNT FILEZILLA")) {
            return Some("FileZilla".to_string());
        }

        // WinSCP: OPTS UTF8 ON early
        if self.commands.len() < 5 && self.commands.iter().any(|c| c.to_uppercase() == "OPTS UTF8 ON") {
            return Some("WinSCP".to_string());
        }

        // lftp: FEAT before authentication
        if self.commands.first().map(|c| c.to_uppercase()) == Some("FEAT".to_string()) {
            return Some("lftp".to_string());
        }

        // curl/wget: Few commands, single operation
        if self.command_count < 6 && !self.commands.iter().any(|c| c.to_uppercase() == "FEAT") {
            return Some("curl/wget/script".to_string());
        }

        // Scanner: Rapid commands, no transfers
        let duration_secs = self.session_start.elapsed().as_secs_f32();
        if duration_secs > 0.0 {
            let rate = self.command_count as f32 / duration_secs;
            if rate > 10.0 && self.bytes_uploaded == 0 && self.bytes_downloaded == 0 {
                return Some("FTP Scanner/Brute-forcer".to_string());
            }
        }

        None
    }

    /// Get command rate (commands per second)
    pub fn command_rate(&self) -> f32 {
        let duration_secs = self.session_start.elapsed().as_secs_f32();
        if duration_secs > 0.0 {
            self.command_count as f32 / duration_secs
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_session_creation() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let session = FtpSession::new(addr);

        assert_eq!(session.state, FtpState::Connected);
        assert_eq!(session.command_count, 0);
        assert_eq!(session.current_dir, PathBuf::from("/"));
    }

    #[test]
    fn test_threat_scoring_base() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let session = FtpSession::new(addr);

        // Base FTP connection: +2
        assert_eq!(session.calculate_threat_level(), 2);
    }

    #[test]
    fn test_threat_scoring_admin_user() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut session = FtpSession::new(addr);

        session.username = Some("admin".to_string());

        // Base +2, admin user +3 = 5
        assert_eq!(session.calculate_threat_level(), 5);
    }

    #[test]
    fn test_client_fingerprinting() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut session = FtpSession::new(addr);

        session.add_command("CLNT FileZilla 3.60.0");

        assert_eq!(session.fingerprint_client(), Some("FileZilla".to_string()));
    }

    #[test]
    fn test_directory_traversal_detection() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let mut session = FtpSession::new(addr);

        session.add_command("CWD ../../../etc");

        assert!(session.directory_traversal_attempted);
    }
}
