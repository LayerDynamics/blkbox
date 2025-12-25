# BlkBox Honeypot: Phases 9-10 Implementation Plan

**Project**: BlkBox - Modern Honeypot with Strike-Back Capabilities
**Document Version**: 1.0
**Date**: 2025-12-25
**Status**: Planning Complete, Ready for Implementation

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Phase 9: FTP/SFTP Honeypot](#phase-9-ftpsftp-honeypot)
3. [Phase 10: Management Dashboard & Analytics](#phase-10-management-dashboard--analytics)
4. [Implementation Timeline](#implementation-timeline)
5. [Success Criteria](#success-criteria)

---

## Executive Summary

This document provides comprehensive implementation plans for the final two phases of the BlkBox honeypot system:

- **Phase 9**: FTP/SFTP Honeypot - Complete FTP protocol implementation with virtual filesystem, upload quarantine, and malware detection
- **Phase 10**: Management Dashboard & Analytics - Web-based monitoring interface with real-time attack visualization, analytics, and export capabilities

**Current Project Status**:
- Phases 1-8: ✅ Complete (100%)
- Phase 9: 📋 Planning Complete
- Phase 10: 📋 Planning Complete
- Overall: ~85% complete

**Estimated Completion**:
- Phase 9: 3 days (FTP implementation)
- Phase 10: 5 days (Dashboard and API)
- Total: 8 days to full system completion

---

# Phase 9: FTP/SFTP Honeypot

## Overview

Implement a production-ready FTP honeypot that follows the established BlkBox architecture patterns. The FTP honeypot will emulate a realistic FTP server with full RFC 959 protocol support, virtual filesystem, file upload quarantine with malware detection, and comprehensive session tracking.

**Priority**: MEDIUM
**Duration**: 3 days
**Dependencies**: Phase 8 (Integration & Main Application)

---

## 9.1 Architecture Overview

### 9.1.1 Design Philosophy

Following the existing honeypot architecture:
- **Trait-based design**: Implements `HoneypotService` trait from `lib_rust/honeypot/traits.rs`
- **Tokio async runtime**: All I/O operations use `tokio::net::TcpListener` and `TcpStream`
- **Event-driven**: Attack events sent via `mpsc::UnboundedSender<AttackEvent>` to FFI layer
- **Shared state**: `Arc<Mutex<>>` for statistics and state management
- **Graceful shutdown**: Oneshot channel pattern for clean service termination
- **Dedicated thread**: Spawns own thread with isolated Tokio runtime (SSH pattern)

### 9.1.2 FTP Protocol State Machine

```
┌─────────────┐
│ CONNECTED   │ ← Initial connection, send 220 banner
└──────┬──────┘
       │ USER <username>
       ▼
┌─────────────┐
│ USER_OK     │ ← Send 331 Password required
└──────┬──────┘
       │ PASS <password>
       ▼
┌─────────────┐
│ LOGGED_IN   │ ← Send 230 Login successful
└──────┬──────┘
       │
       │ PWD, CWD, CDUP, MKD, RMD
       │ PASV, PORT (data connection setup)
       │ LIST, RETR, STOR, DELE
       ▼
┌─────────────┐
│ TRANSFERRING│ ← Active data transfer
└──────┬──────┘
       │
       ▼
     QUIT
```

### 9.1.3 Component Architecture

```
FtpHoneypot
├── Control Connection (port 21)
│   ├── Command Parser
│   ├── State Machine
│   └── Response Generator
├── Data Connection (passive: 1024-65535, active: client-specified)
│   ├── Passive Mode Listener
│   ├── Active Mode Connector
│   └── Transfer Handler
├── Virtual Filesystem
│   ├── Directory Structure
│   ├── File Metadata
│   └── Fake Content Generator
├── Upload Quarantine
│   ├── File Storage
│   ├── Malware Analysis Hooks
│   └── Content Inspection
└── Session Tracker
    ├── Authentication Attempts
    ├── Command History
    └── Threat Scoring
```

---

## 9.2 File Structure

### 9.2.1 Primary Implementation Files

**Main Implementation**: `lib_rust/honeypot/ftp.rs`
- `FtpHoneypot` struct implementing `HoneypotService` trait
- `FtpSession` struct managing per-connection state
- `FtpCommand` enum for all FTP commands
- `FtpState` enum for connection states
- Control connection handler
- Data connection handler (passive and active modes)

**Supporting Modules**:

```
lib_rust/honeypot/ftp/
├── mod.rs                  # Module exports
├── filesystem.rs           # Virtual filesystem implementation
├── quarantine.rs           # Upload handling and storage
├── commands.rs             # Command parsing and responses
└── data_channel.rs         # Data connection management
```

### 9.2.2 Module Registration

Update `lib_rust/honeypot/mod.rs`:
```rust
pub mod ftp;
```

---

## 9.3 FTP Protocol Implementation

### 9.3.1 Core FTP Commands

**Authentication Commands**:
- `USER <username>` - Specify username (always accept)
- `PASS <password>` - Specify password (always accept after USER)
- `ACCT <account>` - Account information (optional)
- `QUIT` - Logout and close connection

**Navigation Commands**:
- `PWD` - Print working directory
- `CWD <path>` - Change working directory
- `CDUP` - Change to parent directory

**Listing Commands**:
- `LIST [path]` - Detailed directory listing
- `NLST [path]` - Name-only listing
- `STAT [path]` - Status information

**File Operations**:
- `RETR <filename>` - Retrieve (download) file
- `STOR <filename>` - Store (upload) file
- `DELE <filename>` - Delete file
- `RMD <dirname>` - Remove directory
- `MKD <dirname>` - Make directory
- `RNFR <from>` / `RNTO <to>` - Rename file/directory

**Data Connection Commands**:
- `PASV` - Enter passive mode (server listens)
- `PORT <h1,h2,h3,h4,p1,p2>` - Active mode (client listens)
- `TYPE <type>` - Transfer type (A=ASCII, I=Binary)
- `MODE <mode>` - Transfer mode (S=Stream)
- `STRU <structure>` - File structure (F=File)

**System Commands**:
- `SYST` - Return system type
- `NOOP` - No operation (keepalive)
- `HELP [command]` - Help information
- `FEAT` - List server features

### 9.3.2 FTP Response Codes (RFC 959)

```
220 - Service ready for new user
221 - Service closing control connection (goodbye)
226 - Transfer complete
227 - Entering passive mode (h1,h2,h3,h4,p1,p2)
230 - User logged in, proceed
331 - User name okay, need password
500 - Syntax error, command unrecognized
501 - Syntax error in parameters or arguments
502 - Command not implemented
530 - Not logged in
550 - Requested action not taken (file not found, permission denied)
```

### 9.3.3 State Management Structures

```rust
enum FtpState {
    Connected,       // Initial state after TCP handshake
    UserProvided,    // After USER command
    LoggedIn,        // After successful PASS
    Renaming,        // After RNFR, waiting for RNTO
}

struct FtpSession {
    // Connection state
    state: FtpState,
    client_addr: SocketAddr,

    // Authentication
    username: Option<String>,
    password: Option<String>,
    auth_attempts: u32,

    // Navigation
    current_dir: PathBuf,

    // Transfer settings
    binary_mode: bool,
    passive_listener: Option<TcpListener>,
    passive_port: Option<u16>,
    active_addr: Option<SocketAddr>,

    // Session tracking
    rename_from: Option<String>,
    command_count: u32,
    bytes_uploaded: u64,
    bytes_downloaded: u64,
    files_accessed: Vec<String>,
    commands: Vec<String>,

    // Timing
    session_start: Instant,
    last_command: Instant,
}
```

---

## 9.4 Virtual Filesystem Design

### 9.4.1 Realistic Directory Structure

Mimic a typical Linux FTP server:

```
/ (virtual root)
├── pub/                          # Public directory
│   ├── README.txt               # Welcome message
│   ├── incoming/                # Upload directory (honeypot target)
│   ├── software/
│   │   ├── linux/
│   │   ├── windows/
│   │   └── mac/
│   └── documents/
│       ├── manual.pdf
│       └── guide.txt
├── home/
│   ├── admin/
│   │   ├── .bash_history        # Fake command history
│   │   ├── .ssh/
│   │   │   └── authorized_keys  # Fake SSH keys
│   │   └── backup/
│   │       ├── database.sql.gz  # Bait file
│   │       └── config.tar.gz    # Bait file
│   ├── ftpuser/
│   │   └── uploads/
│   └── guest/
├── var/
│   ├── log/
│   │   ├── auth.log             # Fake system logs
│   │   ├── syslog
│   │   └── ftp.log
│   └── www/
│       └── html/
│           ├── index.html
│           └── .env             # Bait file with fake credentials
└── etc/
    ├── passwd                    # Fake user database
    ├── group
    └── config/
        └── app.conf
```

### 9.4.2 File Metadata Structure

```rust
struct VirtualFile {
    name: String,
    size: u64,
    is_directory: bool,
    permissions: String,      // e.g., "drwxr-xr-x"
    owner: String,
    group: String,
    modified: DateTime<Utc>,
    content: FileContent,
}

enum FileContent {
    Static(&'static str),                    // Embedded content
    Generated(Box<dyn Fn() -> String>),      // Dynamic content
    Empty,                                   // Empty file
    Large(u64),                              // Large fake file (size only)
}

struct VirtualFilesystem {
    root: HashMap<PathBuf, VirtualFile>,
    current_path: PathBuf,
}
```

### 9.4.3 Bait Files (Attract Attackers)

**High-value targets**:
- `/home/admin/backup/database.sql.gz` - Fake database dump (generates realistic SQL)
- `/home/admin/.ssh/authorized_keys` - Fake SSH keys
- `/var/www/html/.env` - Environment variables with fake credentials
- `/home/admin/.bash_history` - Commands suggesting valuable data locations
- `/etc/passwd` - Realistic but fake user list
- `/home/admin/backup/config.tar.gz` - Configuration archive

**Dynamic Content Examples**:
```rust
// /etc/passwd - Generate realistic user list
VirtualFile {
    name: "passwd".to_string(),
    content: FileContent::Generated(Box::new(|| {
        "root:x:0:0:root:/root:/bin/bash\n\
         admin:x:1000:1000:Administrator:/home/admin:/bin/bash\n\
         ftpuser:x:1001:1001:FTP User:/home/ftpuser:/bin/bash\n\
         www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n".to_string()
    })),
    // ...
}

// /var/log/auth.log - Recent authentication attempts
VirtualFile {
    name: "auth.log".to_string(),
    content: FileContent::Generated(Box::new(|| {
        let now = Utc::now();
        format!(
            "{} server sshd[1234]: Accepted password for admin from 192.168.1.100 port 54321\n\
             {} server sshd[1235]: pam_unix(sshd:session): session opened for user admin\n",
            now.format("%b %d %H:%M:%S"),
            now.format("%b %d %H:%M:%S")
        )
    })),
    // ...
}
```

---

## 9.5 Upload Quarantine System

### 9.5.1 Storage Strategy

All uploaded files are quarantined in isolated storage:

```
/var/blkbox/quarantine/
├── 2025-12-25/
│   ├── 143052-abc123def/
│   │   ├── metadata.json          # Upload metadata
│   │   ├── original.bin           # Raw uploaded file
│   │   └── analysis.json          # Malware analysis results
│   ├── 143102-fed456cba/
│   │   ├── metadata.json
│   │   ├── original.bin
│   │   └── analysis.json
│   └── ...
└── index.db                       # SQLite index of all uploads
```

### 9.5.2 Metadata Structure

```rust
struct UploadMetadata {
    upload_id: String,             // timestamp-hash format
    timestamp: DateTime<Utc>,
    source_ip: String,
    source_port: u16,
    filename: String,              // Original filename from FTP
    virtual_path: String,          // Path in virtual filesystem
    size: u64,
    sha256: String,
    md5: String,
    mime_type: Option<String>,
    file_signature: Vec<u8>,       // First 16 bytes (magic bytes)
    session_id: String,
    username: String,
    transfer_mode: String,         // "ASCII" or "Binary"
}
```

### 9.5.3 Malware Analysis Hooks

```rust
trait MalwareAnalyzer {
    fn analyze(&self, file_path: &Path) -> AnalysisResult;
}

struct ClamAVAnalyzer;      // ClamAV antivirus integration
struct YaraAnalyzer;        // YARA rule matching
struct StaticAnalyzer;      // Basic static analysis

struct AnalysisResult {
    is_malicious: bool,
    confidence: f32,                    // 0.0 - 1.0
    detections: Vec<Detection>,
    entropy: f32,                       // File entropy (randomness)
    embedded_urls: Vec<String>,
    suspicious_strings: Vec<String>,
    file_type: String,
    threat_category: Option<String>,    // "trojan", "ransomware", etc.
}

struct Detection {
    scanner: String,            // "clamav", "yara", "static"
    signature: String,          // Signature/rule name
    severity: String,           // "critical", "high", "medium", "low"
}
```

### 9.5.4 Upload Processing Flow

```
1. Client sends: STOR malware.exe
2. Server responds: 150 Opening BINARY mode data connection for malware.exe
3. Create quarantine directory: /var/blkbox/quarantine/2025-12-25/143052-abc123/
4. Stream data to: original.bin
5. On transfer complete:
   a. Calculate SHA-256 and MD5 hashes
   b. Detect file type from magic bytes
   c. Write metadata.json
   d. Respond: 226 Transfer complete
   e. Queue for async malware analysis
6. Background analysis (async):
   a. Run ClamAV scan (if available)
   b. Run YARA rules
   c. Calculate entropy
   d. Extract strings and URLs
   e. Write analysis.json
   f. Store results in ftp_uploads table
   g. Generate high-severity attack event if malware detected
```

---

## 9.6 Session Management & Threat Scoring

### 9.6.1 Authentication Tracking

```rust
struct AuthAttempt {
    timestamp: DateTime<Utc>,
    username: String,
    password: String,
    success: bool,          // Always true in honeypot
    client_banner: Option<String>,
}

// Track common attack patterns:
// - admin, root, ftp, anonymous, test, guest
// - Brute force attempts (multiple rapid AUTH attempts)
// - Dictionary attacks (common passwords)
```

### 9.6.2 Command History Tracking

```rust
struct CommandRecord {
    timestamp: DateTime<Utc>,
    command: String,
    arguments: String,
    response_code: u16,
    state_before: FtpState,
    state_after: FtpState,
    execution_time_ms: u64,
}
```

### 9.6.3 Threat Scoring Algorithm

```rust
fn calculate_ftp_threat_level(session: &FtpSession) -> u8 {
    let mut threat = 0u8;

    // Base level for FTP connection
    threat += 2;

    // Anonymous login attempt: +1
    if session.username.as_deref() == Some("anonymous") {
        threat += 1;
    }

    // Admin/root username: +3
    if matches!(session.username.as_deref(), Some("admin" | "root")) {
        threat += 3;
    }

    // Multiple authentication attempts: +2
    if session.auth_attempts > 3 {
        threat += 2;
    }

    // Accessed sensitive paths: +4
    let sensitive_paths = ["/etc/shadow", "/etc/passwd", "/.ssh/", "/root/"];
    if session.files_accessed.iter().any(|f| {
        sensitive_paths.iter().any(|p| f.contains(p))
    }) {
        threat += 4;
    }

    // Uploaded executable files: +5
    if session.uploaded_executables() {
        threat += 5;
    }

    // Downloaded backup/database files: +3
    if session.downloaded_sensitive_files() {
        threat += 3;
    }

    // High command rate (automation/scanner): +2
    let commands_per_second = session.command_count as f32
        / session.session_start.elapsed().as_secs_f32();
    if commands_per_second > 5.0 {
        threat += 2;
    }

    // Directory traversal attempts (../ in paths): +4
    if session.directory_traversal_detected() {
        threat += 4;
    }

    // Attempted dangerous commands: +3
    let dangerous_cmds = ["SITE EXEC", "SITE CHMOD", "DELE /etc/", "RMD /"];
    if session.commands.iter().any(|cmd| {
        dangerous_cmds.iter().any(|d| cmd.contains(d))
    }) {
        threat += 3;
    }

    // Cap at 10
    threat.min(10)
}
```

### 9.6.4 FTP Client Fingerprinting

```rust
fn fingerprint_ftp_client(session: &FtpSession) -> Option<String> {
    let command_sequence = &session.commands;

    // FileZilla: Sends CLNT command with version
    if command_sequence.iter().any(|c| c.starts_with("CLNT FileZilla")) {
        return Some("FileZilla".to_string());
    }

    // WinSCP: Sends OPTS UTF8 ON early
    if command_sequence.len() < 5
        && command_sequence.iter().any(|c| c == "OPTS UTF8 ON") {
        return Some("WinSCP".to_string());
    }

    // lftp: Sends FEAT before authentication
    if command_sequence.first().map(|c| c.as_str()) == Some("FEAT") {
        return Some("lftp".to_string());
    }

    // curl/wget: Very few commands, no FEAT, single operation
    if session.command_count < 5
        && !command_sequence.iter().any(|c| c == "FEAT") {
        return Some("curl/wget/script".to_string());
    }

    // Scanner: Rapid commands, common usernames, no actual transfers
    if session.command_rate() > 10.0
        && matches!(session.username.as_deref(),
                   Some("admin" | "root" | "test" | "ftp"))
        && session.bytes_uploaded == 0
        && session.bytes_downloaded == 0 {
        return Some("FTP Scanner/Brute-forcer".to_string());
    }

    None
}
```

---

## 9.7 FFI Integration

### 9.7.1 Service Registration

Update `lib_rust/lib.rs` to handle FTP honeypot:

```rust
#[no_mangle]
pub extern "C" fn blkbox_start_honeypot(
    runtime: *mut BlkBoxRuntime,
    service_type: u8,
    port: u16,
    config_json: *const c_char,
) -> i32 {
    // ... existing code ...

    match service_type {
        // ... existing cases ...

        6 => { // ServiceType::FTP
            use honeypot::ftp::FtpHoneypot;
            use honeypot::traits::HoneypotService;

            let mut honeypot = FtpHoneypot::new(port, service_id)
                .with_event_sender(runtime.event_sender.clone());

            let start_result = runtime.tokio_runtime.block_on(async {
                honeypot.start().await
            });

            if start_result.is_ok() {
                let shutdown = honeypot.take_shutdown_tx();
                runtime.services.insert(service_id, shutdown);
                0  // Success
            } else {
                -1  // Error
            }
        }

        _ => -1  // Unknown service type
    }
}
```

### 9.7.2 Event Generation

Generate `AttackEvent` for each significant FTP action:

```rust
// On authentication
let event = AttackEvent {
    timestamp: Utc::now().to_rfc3339(),
    source_ip: session.client_addr.ip().to_string(),
    source_port: session.client_addr.port(),
    service_type: ServiceType::FTP,
    service_id: self.service_id,
    user_agent: Some(format!("FTP:{}:{}", username, password)),
    payload: format!("USER {} | PASS {}", username, password),
    threat_level: calculate_ftp_threat_level(session),
    fingerprint: fingerprint_ftp_client(session),
    // Additional FTP-specific fields in metadata
};

self.event_sender.send(event)?;
```

### 9.7.3 Database Schema Extensions

Add FTP-specific tables:

```sql
-- FTP upload tracking
CREATE TABLE IF NOT EXISTS ftp_uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_id INTEGER NOT NULL,
    upload_id TEXT NOT NULL UNIQUE,
    filename TEXT NOT NULL,
    virtual_path TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    md5 TEXT NOT NULL,
    mime_type TEXT,
    file_signature BLOB,
    quarantine_path TEXT NOT NULL,
    malware_detected BOOLEAN DEFAULT FALSE,
    analysis_results TEXT,
    entropy REAL,
    threat_category TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(attack_id) REFERENCES attacks(id) ON DELETE CASCADE
);

CREATE INDEX idx_ftp_uploads_sha256 ON ftp_uploads(sha256);
CREATE INDEX idx_ftp_uploads_malware ON ftp_uploads(malware_detected);

-- FTP command history
CREATE TABLE IF NOT EXISTS ftp_commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_id INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    command TEXT NOT NULL,
    arguments TEXT,
    response_code INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(attack_id) REFERENCES attacks(id) ON DELETE CASCADE
);

CREATE INDEX idx_ftp_commands_session ON ftp_commands(session_id);
CREATE INDEX idx_ftp_commands_command ON ftp_commands(command);
```

---

## 9.8 Implementation Sequence

### Day 1: Core Protocol & Basic Commands

**Morning (4 hours)**:
1. Create `lib_rust/honeypot/ftp.rs` with basic structure
2. Implement `FtpHoneypot` struct
3. Implement `HoneypotService` trait
4. Create TCP listener and connection handler
5. Implement state machine (FtpState enum)
6. Basic command parser (USER, PASS, QUIT, SYST, NOOP, PWD)

**Afternoon (4 hours)**:
7. Implement authentication flow (always succeed)
8. Response generation for basic commands
9. Session state tracking
10. Add FTP case to FFI layer (lib.rs)
11. Basic integration test (connect, login, quit)

**Success Criteria**:
- Can connect with FTP client
- Authentication works (USER → PASS → 230)
- Can cleanly disconnect
- Events generated and logged

### Day 2: Virtual Filesystem & Data Connections

**Morning (4 hours)**:
1. Create `lib_rust/honeypot/ftp/filesystem.rs`
2. Implement directory tree structure
3. Create realistic file hierarchy (/pub, /home, /etc, /var)
4. Implement navigation (CWD, CDUP, PWD)
5. Implement listing (LIST, NLST with Unix format)
6. Add bait files with metadata

**Afternoon (4 hours)**:
7. Create `lib_rust/honeypot/ftp/data_channel.rs`
8. Implement PASV command and passive mode
9. Dynamic port allocation (1024-65535)
10. File download (RETR) with fake content
11. Binary vs ASCII mode (TYPE command)
12. Integration test: ls, cd, download file

**Success Criteria**:
- Directory listings show realistic files
- Navigation works correctly
- Passive mode establishes data connection
- Can download files successfully

### Day 3: Upload Quarantine & Advanced Features

**Morning (4 hours)**:
1. Create `lib_rust/honeypot/ftp/quarantine.rs`
2. Implement STOR command (file upload)
3. Quarantine directory creation
4. File streaming to disk
5. SHA-256 and MD5 hashing
6. File type detection (magic bytes)
7. Metadata JSON generation

**Afternoon (4 hours)**:
8. Implement malware analysis hooks
9. ClamAV integration (optional)
10. Static analysis (entropy, strings)
11. Database integration (ftp_uploads table)
12. Command tracking (ftp_commands table)
13. Threat scoring refinement
14. Client fingerprinting
15. Comprehensive testing

**Success Criteria**:
- Can upload files successfully
- Files quarantined properly
- Metadata captured
- Malware analysis queued
- All events logged to database

---

## 9.9 Testing Strategy

### 9.9.1 Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_parsing() {
        assert_eq!(
            FtpCommand::parse("USER admin\r\n"),
            FtpCommand::User("admin".to_string())
        );

        assert_eq!(
            FtpCommand::parse("PASS secret123\r\n"),
            FtpCommand::Pass("secret123".to_string())
        );

        assert_eq!(
            FtpCommand::parse("PORT 192,168,1,100,31,144\r\n"),
            FtpCommand::Port(/* parsed address */)
        );
    }

    #[test]
    fn test_virtual_filesystem() {
        let fs = VirtualFilesystem::new();

        // Test navigation
        assert_eq!(fs.pwd(), "/");
        fs.chdir("/pub").unwrap();
        assert_eq!(fs.pwd(), "/pub");

        // Test listing
        let files = fs.list_directory("/pub").unwrap();
        assert!(files.iter().any(|f| f.name == "README.txt"));
    }

    #[test]
    fn test_quarantine_storage() {
        let quarantine = UploadQuarantine::new("/tmp/test_quarantine");

        let upload_id = quarantine.store_upload(
            "test.bin",
            b"test content",
            "1.2.3.4",
            12345,
        ).unwrap();

        assert!(quarantine.exists(&upload_id));
        assert_eq!(quarantine.get_size(&upload_id).unwrap(), 12);
    }
}
```

### 9.9.2 Integration Tests

```rust
#[tokio::test]
async fn test_full_ftp_session() {
    // Start honeypot
    let honeypot = FtpHoneypot::new(2121, 1);
    honeypot.start().await.unwrap();

    // Connect
    let mut client = TcpStream::connect("127.0.0.1:2121").await.unwrap();

    // Read banner
    let banner = read_line(&mut client).await;
    assert!(banner.starts_with("220"));

    // Login
    send_command(&mut client, "USER admin").await;
    let response = read_line(&mut client).await;
    assert!(response.starts_with("331"));

    send_command(&mut client, "PASS password").await;
    let response = read_line(&mut client).await;
    assert!(response.starts_with("230"));

    // List directory
    send_command(&mut client, "LIST").await;
    // ... verify directory listing

    // Quit
    send_command(&mut client, "QUIT").await;
    let response = read_line(&mut client).await;
    assert!(response.starts_with("221"));
}
```

### 9.9.3 Real-World Testing

**Command-line FTP client**:
```bash
ftp -n localhost 21
> user admin password
> ls
> cd pub
> get README.txt
> put malware.exe
> quit
```

**FileZilla GUI client**:
- Host: localhost
- Port: 21
- Username: admin
- Password: (anything)
- Test navigation, upload, download

**Nmap FTP scripts**:
```bash
nmap -p 21 --script ftp-anon,ftp-brute localhost
```

---

## 9.10 Security Considerations

### 9.10.1 Quarantine Isolation

**Critical requirements**:
- Quarantine directory must be outside web server document root
- Mount with `noexec` flag to prevent execution
- Implement disk quota to prevent DoS (max 10GB default)
- Regular rotation/cleanup (delete files older than 90 days)
- Backup to external storage before deletion

### 9.10.2 Resource Limits

```rust
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;      // 100MB per file
const MAX_SESSIONS: usize = 100;                    // Max concurrent sessions
const MAX_COMMANDS_PER_SESSION: u32 = 1000;        // Prevent command flood
const SESSION_TIMEOUT: Duration = Duration::from_secs(300);     // 5 min idle
const DATA_TRANSFER_TIMEOUT: Duration = Duration::from_secs(60); // 1 min transfer
const MAX_DAILY_UPLOADS: usize = 1000;             // Prevent storage exhaustion
```

### 9.10.3 Path Traversal Prevention

```rust
fn sanitize_path(user_path: &str, virtual_root: &Path) -> Result<PathBuf> {
    let requested = Path::new(user_path);
    let absolute = virtual_root.join(requested).canonicalize()?;

    // Ensure path stays within virtual root
    if !absolute.starts_with(virtual_root) {
        return Err(anyhow!("Path traversal attempt detected"));
    }

    Ok(absolute)
}
```

---

# Phase 10: Management Dashboard & Analytics

## Overview

Implement a comprehensive web-based management dashboard for monitoring, controlling, and analyzing the BlkBox honeypot system. Provides real-time attack visualization, analytics, attacker profiling, data export, and alert management.

**Priority**: MEDIUM
**Duration**: 5 days
**Dependencies**: Phase 8 (Integration & Main Application)

---

## 10.1 Architecture Overview

### 10.1.1 Technology Stack

**Backend**:
- Deno native HTTP server (`Deno.serve`)
- TypeScript for type safety
- FFI integration for database queries
- Server-Sent Events (SSE) for real-time updates

**Frontend**:
- Vanilla HTML/CSS/JavaScript (no build step)
- Chart.js for analytics visualization
- Leaflet for geographic mapping
- Dark theme UI (modern, professional)

**Port**: 9000 (configurable via `config.json`)

### 10.1.2 System Architecture

```
┌──────────────────────────────────────────────┐
│          Web Browser (Dashboard UI)          │
│  - Real-time attack feed (SSE)              │
│  - Charts, maps, statistics                 │
│  - Attacker profiles                        │
│  - Export tools                             │
└─────────────────┬────────────────────────────┘
                  │ HTTP/SSE
                  ▼
┌──────────────────────────────────────────────┐
│       Management Server (Deno HTTP)          │
│  - REST API endpoints                       │
│  - SSE event streaming                      │
│  - Static file serving                      │
│  - Authentication & CORS                    │
└─────────────────┬────────────────────────────┘
                  │ FFI Calls
                  ▼
┌──────────────────────────────────────────────┐
│         BlkBox Rust Core (FFI)               │
│  - Database queries (SQLite)                │
│  - Event stream access                      │
│  - Statistics aggregation                   │
│  - Honeypot control                         │
└──────────────────────────────────────────────┘
```

---

## 10.2 API Endpoints

### 10.2.1 System Status & Health

**GET `/api/health`**
- Returns server health status
- No authentication required

Request: None

Response:
```json
{
  "status": "healthy",
  "uptime": 3600,
  "timestamp": "2025-12-25T14:30:52Z",
  "version": "1.0.0"
}
```

**GET `/api/status`**
- Returns comprehensive system statistics

Response:
```json
{
  "honeypots": {
    "total": 5,
    "running": 3,
    "services": [
      {"type": "http", "port": 8080, "status": "running", "uptime": 3600},
      {"type": "ssh", "port": 2222, "status": "running", "uptime": 3600},
      {"type": "ftp", "port": 21, "status": "stopped", "uptime": 0}
    ]
  },
  "attacks": {
    "total": 1523,
    "last_hour": 45,
    "last_24h": 892,
    "unique_ips": 234
  },
  "strikeback": {
    "enabled": false,
    "dry_run": true,
    "active_payloads": 0,
    "pending_approvals": 3
  },
  "database": {
    "size_mb": 128.5,
    "attack_count": 1523,
    "session_count": 456
  }
}
```

### 10.2.2 Attack Data

**GET `/api/attacks`**
- Returns paginated list of recent attacks

Query Parameters:
- `limit` (default: 100, max: 1000)
- `offset` (default: 0)
- `service_type` (optional filter)
- `min_threat` (optional, 0-10)

Response:
```json
{
  "total": 1523,
  "limit": 100,
  "offset": 0,
  "attacks": [
    {
      "id": 1523,
      "timestamp": "2025-12-25T14:30:00Z",
      "source_ip": "203.0.113.42",
      "source_port": 54321,
      "service_type": "SSH",
      "service_id": 2,
      "threat_level": 8,
      "payload": "SSH login attempt: root:password123",
      "user_agent": "SSH-2.0-OpenSSH_8.2",
      "fingerprint": "hassh:...",
      "geolocation": {
        "country": "US",
        "country_name": "United States",
        "city": "New York",
        "latitude": 40.7128,
        "longitude": -74.0060
      }
    }
    // ... more attacks
  ]
}
```

**GET `/api/attacks/:id`**
- Returns detailed information about a specific attack

Response:
```json
{
  "attack": {
    "id": 1523,
    "timestamp": "2025-12-25T14:30:00Z",
    "source_ip": "203.0.113.42",
    "source_port": 54321,
    "service_type": "SSH",
    "threat_level": 8,
    "payload": "SSH login attempt: root:password123",
    "session_id": "sess_abc123",
    "fingerprint": "hassh:..."
  },
  "geolocation": {
    "country": "US",
    "country_name": "United States",
    "region": "NY",
    "city": "New York",
    "latitude": 40.7128,
    "longitude": -74.0060,
    "timezone": "America/New_York",
    "isp": "Example ISP"
  },
  "session": {
    "session_id": "sess_abc123",
    "attack_count": 12,
    "threat_escalation": true,
    "first_seen": "2025-12-25T14:20:00Z",
    "last_seen": "2025-12-25T14:30:00Z"
  },
  "related_attacks": [
    {"id": 1520, "timestamp": "2025-12-25T14:28:00Z"},
    {"id": 1518, "timestamp": "2025-12-25T14:25:00Z"}
  ]
}
```

**GET `/api/attacks/stream`**
- Server-Sent Events (SSE) stream of real-time attacks

Response (SSE format):
```
event: attack
data: {"id": 1524, "timestamp": "2025-12-25T14:31:00Z", "source_ip": "203.0.113.43", ...}

event: attack
data: {"id": 1525, "timestamp": "2025-12-25T14:31:05Z", "source_ip": "198.51.100.22", ...}

event: heartbeat
data: {"timestamp": "2025-12-25T14:31:30Z"}
```

### 10.2.3 Analytics & Statistics

**GET `/api/analytics/summary`**
- Returns dashboard summary statistics

Query Parameters:
- `period` (1h, 24h, 7d, 30d, all)

Response:
```json
{
  "period": "24h",
  "total_attacks": 892,
  "unique_ips": 156,
  "by_service": {
    "HTTP": 523,
    "SSH": 289,
    "PostgreSQL": 45,
    "FTP": 35
  },
  "by_threat_level": {
    "critical": 23,   // 9-10
    "high": 145,      // 7-8
    "medium": 456,    // 4-6
    "low": 268        // 0-3
  },
  "top_ips": [
    {"ip": "203.0.113.42", "count": 45, "threat_avg": 7.2},
    {"ip": "198.51.100.22", "count": 38, "threat_avg": 6.8},
    {"ip": "192.0.2.15", "count": 32, "threat_avg": 8.1}
  ],
  "geography": {
    "US": 234,
    "CN": 123,
    "RU": 89,
    "DE": 45
  }
}
```

**GET `/api/analytics/timeline`**
- Returns attack timeline data for charts

Query Parameters:
- `interval` (1m, 5m, 1h, 1d)
- `period` (24h, 7d, 30d)

Response:
```json
{
  "interval": "1h",
  "period": "24h",
  "data": [
    {"timestamp": "2025-12-25T00:00:00Z", "count": 34, "avg_threat": 5.2},
    {"timestamp": "2025-12-25T01:00:00Z", "count": 28, "avg_threat": 4.8},
    // ... 24 entries
  ]
}
```

**GET `/api/analytics/geography`**
- Returns geographic distribution for map visualization

Response:
```json
{
  "countries": [
    {
      "code": "US",
      "name": "United States",
      "count": 234,
      "avg_threat": 6.5,
      "coordinates": [39.8283, -98.5795]
    }
  ],
  "cities": [
    {
      "name": "New York, US",
      "count": 45,
      "coordinates": [40.7128, -74.0060]
    }
  ]
}
```

### 10.2.4 Attacker Profiling

**GET `/api/attackers/:ip`**
- Returns comprehensive profile for specific IP

Response:
```json
{
  "ip": "203.0.113.42",
  "first_seen": "2025-12-24T10:30:00Z",
  "last_seen": "2025-12-25T14:30:00Z",
  "attack_count": 67,
  "threat_level_avg": 7.2,
  "threat_level_max": 9,
  "services_targeted": ["SSH", "HTTP", "PostgreSQL"],
  "geolocation": {
    "country": "US",
    "city": "New York",
    "coordinates": [40.7128, -74.0060]
  },
  "sessions": [
    {
      "session_id": "sess_abc123",
      "attack_count": 12,
      "duration": 180,
      "threat_escalation": true
    }
  ],
  "fingerprints": [
    "SSH-2.0-OpenSSH_8.2",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
  ],
  "recent_attacks": [
    {
      "id": 1523,
      "timestamp": "2025-12-25T14:30:00Z",
      "service_type": "SSH",
      "threat_level": 8
    }
  ],
  "strikeback_deployed": false
}
```

**GET `/api/attackers/top`**
- Returns top attackers by various metrics

Query Parameters:
- `metric` (count, threat, persistence)
- `limit` (default: 10)

Response:
```json
{
  "metric": "threat",
  "attackers": [
    {
      "ip": "203.0.113.42",
      "count": 67,
      "avg_threat": 8.5,
      "last_seen": "2025-12-25T14:30:00Z"
    }
  ]
}
```

### 10.2.5 Strike-Back Management

**GET `/api/strikeback/pending`**
- Returns pending strike-back approvals

Response:
```json
{
  "pending": [
    {
      "deployment_id": "deploy_abc123",
      "attack_id": 1520,
      "attacker_ip": "203.0.113.42",
      "threat_score": 8.5,
      "payload_type": "SystemInfo",
      "timestamp": "2025-12-25T14:28:00Z",
      "reason": "High threat score, persistent attacks"
    }
  ]
}
```

**POST `/api/strikeback/approve/:deployment_id`**
- Approve a pending strike-back deployment

Request Body:
```json
{
  "approver": "admin",
  "notes": "Approved due to persistent scanning"
}
```

Response:
```json
{
  "success": true,
  "payload_url": "http://localhost:8443/p/abc123def456",
  "deployment_id": "deploy_abc123"
}
```

**GET `/api/strikeback/payloads`**
- List active payloads

Response:
```json
{
  "active_payloads": [
    {
      "payload_id": "abc123def456",
      "payload_type": "SystemInfo",
      "target_ip": "203.0.113.42",
      "created_at": "2025-12-25T14:28:00Z",
      "expires_at": "2025-12-26T14:28:00Z",
      "delivery_count": 1,
      "callback_count": 3,
      "last_callback": "2025-12-25T14:30:00Z"
    }
  ]
}
```

### 10.2.6 Export Functionality

**GET `/api/export/json`**
- Export attack data as JSON

Query Parameters:
- `since` (timestamp, optional)
- `service_type` (optional)
- `min_threat` (optional)

Response: JSON file download
```
Content-Type: application/json
Content-Disposition: attachment; filename="blkbox-export-20251225-143052.json"

[
  {
    "id": 1523,
    "timestamp": "2025-12-25T14:30:00Z",
    ...
  }
]
```

**GET `/api/export/csv`**
- Export attack data as CSV

Query Parameters: Same as JSON

Response: CSV file download
```
Content-Type: text/csv
Content-Disposition: attachment; filename="blkbox-export-20251225-143052.csv"

id,timestamp,source_ip,service_type,threat_level,payload
1523,2025-12-25T14:30:00Z,203.0.113.42,SSH,8,"SSH login: root:password123"
...
```

**GET `/api/export/pcap`**
- Export network capture data (if available)

Response: PCAP file download

**POST `/api/export/report`**
- Generate PDF report

Request Body:
```json
{
  "period": "24h",
  "include_charts": true,
  "include_attackers": true,
  "include_geography": true
}
```

Response: PDF file download

### 10.2.7 Honeypot Control

**POST `/api/honeypots/:service_id/start`**
- Start a honeypot service

Response:
```json
{
  "success": true,
  "service_id": 2,
  "status": "running"
}
```

**POST `/api/honeypots/:service_id/stop`**
- Stop a honeypot service

**POST `/api/honeypots/:service_id/restart`**
- Restart a honeypot service

**GET `/api/honeypots`**
- List all honeypot services

Response:
```json
{
  "honeypots": [
    {
      "service_id": 1,
      "type": "HTTP",
      "port": 8080,
      "status": "running",
      "uptime": 3600,
      "total_connections": 523,
      "active_connections": 3
    }
  ]
}
```

---

## 10.3 Server-Sent Events (SSE) Implementation

### 10.3.1 SSE Architecture

```typescript
export class SSEManager {
  private clients: Set<WritableStreamDefaultWriter> = new Set();
  private eventQueue: AttackEvent[] = [];

  async addClient(writer: WritableStreamDefaultWriter): Promise<void> {
    this.clients.add(writer);

    // Send initial connection message
    await this.sendToClient(writer, {
      event: "connected",
      data: { timestamp: new Date().toISOString() }
    });
  }

  removeClient(writer: WritableStreamDefaultWriter): void {
    this.clients.delete(writer);
  }

  async broadcast(event: SSEEvent): Promise<void> {
    const encoder = new TextEncoder();
    const message = `event: ${event.event}\ndata: ${JSON.stringify(event.data)}\n\n`;
    const data = encoder.encode(message);

    // Send to all connected clients
    for (const client of this.clients) {
      try {
        await client.write(data);
      } catch (error) {
        // Client disconnected, remove it
        this.clients.delete(client);
      }
    }
  }

  async sendHeartbeat(): Promise<void> {
    await this.broadcast({
      event: "heartbeat",
      data: { timestamp: new Date().toISOString() }
    });
  }
}
```

### 10.3.2 SSE Endpoint Handler

```typescript
async handleSSE(req: Request): Promise<Response> {
  const stream = new ReadableStream({
    start: async (controller) => {
      const encoder = new TextEncoder();
      const writer = controller;

      // Add client to SSE manager
      this.sseManager.addClient(writer);

      // Keep connection alive
      const heartbeatInterval = setInterval(async () => {
        try {
          await this.sseManager.sendHeartbeat();
        } catch (error) {
          clearInterval(heartbeatInterval);
          this.sseManager.removeClient(writer);
        }
      }, 30000); // 30 second heartbeat

      // Listen for new attacks
      this.eventPipeline.on("attack", async (event) => {
        await this.sseManager.broadcast({
          event: "attack",
          data: event
        });
      });
    },

    cancel() {
      // Client disconnected
      this.sseManager.removeClient(writer);
    }
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "X-Accel-Buffering": "no" // Disable nginx buffering
    }
  });
}
```

### 10.3.3 Client-Side SSE Handler

```javascript
// dashboard.js
const eventSource = new EventSource('/api/attacks/stream');

eventSource.addEventListener('attack', (e) => {
  const attack = JSON.parse(e.data);
  addAttackToFeed(attack);
  updateStatistics(attack);
  updateMap(attack);
});

eventSource.addEventListener('heartbeat', (e) => {
  console.log('Connection alive:', e.data);
  updateConnectionStatus('connected');
});

eventSource.onerror = (e) => {
  console.error('SSE error:', e);
  updateConnectionStatus('disconnected');

  // Reconnect after 5 seconds
  setTimeout(() => {
    eventSource.close();
    location.reload();
  }, 5000);
};
```

---

## 10.4 Dashboard UI Implementation

### 10.4.1 HTML Structure

**File**: `blkbox/server/static/dashboard.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BlkBox Dashboard</title>
  <link rel="stylesheet" href="/static/dashboard.css">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header class="header">
      <h1>🐝 BlkBox Honeypot Dashboard</h1>
      <div class="connection-status">
        <span class="status-indicator" id="status-indicator"></span>
        <span id="status-text">Connected</span>
      </div>
    </header>

    <!-- Statistics Cards -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value" id="total-attacks">0</div>
        <div class="stat-label">Total Attacks</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="unique-ips">0</div>
        <div class="stat-label">Unique IPs</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="http-attacks">0</div>
        <div class="stat-label">HTTP Attacks</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="ssh-attacks">0</div>
        <div class="stat-label">SSH Attacks</div>
      </div>
    </div>

    <!-- Main Content Grid -->
    <div class="main-grid">
      <!-- Real-time Attack Feed -->
      <section class="panel attack-feed">
        <h2>Real-Time Attack Feed</h2>
        <div id="attack-list" class="attack-list"></div>
      </section>

      <!-- Attack Timeline Chart -->
      <section class="panel">
        <h2>Attack Timeline (24h)</h2>
        <canvas id="timeline-chart"></canvas>
      </section>

      <!-- Geographic Map -->
      <section class="panel map-panel">
        <h2>Attack Origins</h2>
        <div id="map" class="map"></div>
      </section>

      <!-- Threat Distribution -->
      <section class="panel">
        <h2>Threat Level Distribution</h2>
        <canvas id="threat-chart"></canvas>
      </section>

      <!-- Service Distribution -->
      <section class="panel">
        <h2>Attacks by Service</h2>
        <canvas id="service-chart"></canvas>
      </section>

      <!-- Top Attackers -->
      <section class="panel">
        <h2>Top Attackers</h2>
        <div id="top-attackers" class="top-attackers"></div>
      </section>
    </div>

    <!-- Strike-Back Panel (if enabled) -->
    <section class="panel strikeback-panel" id="strikeback-panel" style="display: none;">
      <h2>⚡ Pending Strike-Back Approvals</h2>
      <div id="pending-approvals"></div>
    </section>
  </div>

  <script src="/static/dashboard.js"></script>
</body>
</html>
```

### 10.4.2 CSS Styling

**File**: `blkbox/server/static/dashboard.css`

```css
:root {
  --bg-primary: #0a0a0a;
  --bg-secondary: #1a1a1a;
  --bg-tertiary: #2a2a2a;
  --text-primary: #ffffff;
  --text-secondary: #aaaaaa;
  --border-color: #333333;
  --accent-red: #ff6b6b;
  --accent-orange: #ffa500;
  --accent-green: #4caf50;
  --accent-blue: #42a5f5;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  line-height: 1.6;
  padding: 20px;
}

.container {
  max-width: 1800px;
  margin: 0 auto;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
  padding-bottom: 20px;
  border-bottom: 2px solid var(--border-color);
}

.header h1 {
  font-size: 2em;
  font-weight: 600;
}

.connection-status {
  display: flex;
  align-items: center;
  gap: 10px;
}

.status-indicator {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: var(--accent-green);
  animation: pulse 2s infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.stat-card {
  background: var(--bg-secondary);
  padding: 25px;
  border-radius: 8px;
  border: 1px solid var(--border-color);
  text-align: center;
}

.stat-value {
  font-size: 2.5em;
  font-weight: bold;
  color: var(--accent-red);
  margin-bottom: 5px;
}

.stat-label {
  color: var(--text-secondary);
  font-size: 0.9em;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.main-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
  gap: 20px;
}

.panel {
  background: var(--bg-secondary);
  padding: 25px;
  border-radius: 8px;
  border: 1px solid var(--border-color);
}

.panel h2 {
  font-size: 1.3em;
  margin-bottom: 20px;
  color: var(--text-primary);
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 10px;
}

.attack-feed {
  grid-column: span 2;
}

.attack-list {
  max-height: 400px;
  overflow-y: auto;
}

.attack-item {
  padding: 12px;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
  transition: background 0.2s;
}

.attack-item:hover {
  background: var(--bg-tertiary);
}

.attack-item.new {
  background: rgba(255, 107, 107, 0.1);
  animation: fadeIn 0.5s;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(-10px); }
  to { opacity: 1; transform: translateY(0); }
}

.attack-time {
  color: var(--text-secondary);
  font-size: 0.85em;
}

.attack-ip {
  font-family: monospace;
  color: var(--accent-blue);
  font-weight: 600;
}

.attack-service {
  background: var(--bg-tertiary);
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 0.85em;
}

.threat-badge {
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 0.85em;
  font-weight: 600;
}

.threat-critical { background: var(--accent-red); color: white; }
.threat-high { background: var(--accent-orange); color: white; }
.threat-medium { background: #ffd700; color: #0a0a0a; }
.threat-low { background: var(--accent-green); color: white; }

.map {
  height: 400px;
  border-radius: 4px;
}

.map-panel {
  grid-column: span 2;
}

.top-attackers {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.attacker-item {
  display: flex;
  justify-content: space-between;
  padding: 10px;
  background: var(--bg-tertiary);
  border-radius: 4px;
  cursor: pointer;
  transition: background 0.2s;
}

.attacker-item:hover {
  background: #333;
}

.strikeback-panel {
  background: rgba(255, 107, 107, 0.05);
  border-color: var(--accent-red);
}

.approval-item {
  background: var(--bg-tertiary);
  padding: 15px;
  border-radius: 4px;
  margin-bottom: 10px;
}

.approval-actions {
  display: flex;
  gap: 10px;
  margin-top: 10px;
}

button {
  background: var(--accent-blue);
  color: white;
  border: none;
  padding: 8px 16px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9em;
  transition: background 0.2s;
}

button:hover {
  background: #1976d2;
}

button.danger {
  background: var(--accent-red);
}

button.danger:hover {
  background: #d32f2f;
}
```

### 10.4.3 JavaScript Logic

**File**: `blkbox/server/static/dashboard.js`

```javascript
// Global state
const state = {
  attacks: [],
  stats: {},
  map: null,
  charts: {},
  sseConnected: false
};

// Initialize dashboard
async function init() {
  console.log('🐝 BlkBox Dashboard initializing...');

  // Load initial data
  await loadStats();
  await loadRecentAttacks();

  // Initialize visualizations
  initMap();
  initCharts();

  // Start SSE connection
  connectSSE();

  // Refresh stats every 30 seconds
  setInterval(loadStats, 30000);
}

// Load system statistics
async function loadStats() {
  try {
    const response = await fetch('/api/analytics/summary?period=24h');
    const data = await response.json();
    state.stats = data;

    updateStatsCards(data);
    updateCharts(data);
  } catch (error) {
    console.error('Failed to load stats:', error);
  }
}

// Update statistics cards
function updateStatsCards(stats) {
  document.getElementById('total-attacks').textContent = stats.total_attacks.toLocaleString();
  document.getElementById('unique-ips').textContent = stats.unique_ips.toLocaleString();
  document.getElementById('http-attacks').textContent = (stats.by_service.HTTP || 0).toLocaleString();
  document.getElementById('ssh-attacks').textContent = (stats.by_service.SSH || 0).toLocaleString();
}

// Load recent attacks
async function loadRecentAttacks() {
  try {
    const response = await fetch('/api/attacks?limit=50');
    const data = await response.json();
    state.attacks = data.attacks;

    renderAttackFeed(data.attacks);
  } catch (error) {
    console.error('Failed to load attacks:', error);
  }
}

// Render attack feed
function renderAttackFeed(attacks) {
  const attackList = document.getElementById('attack-list');
  attackList.innerHTML = '';

  attacks.forEach(attack => {
    const item = createAttackItem(attack);
    attackList.appendChild(item);
  });
}

// Create attack item element
function createAttackItem(attack) {
  const div = document.createElement('div');
  div.className = 'attack-item';

  const threatClass = getThreatClass(attack.threat_level);

  div.innerHTML = `
    <div>
      <span class="attack-time">${formatTime(attack.timestamp)}</span>
      <span class="attack-ip">${attack.source_ip}</span>
      <span class="attack-service">${attack.service_type}</span>
    </div>
    <div>
      <span class="threat-badge ${threatClass}">
        Threat: ${attack.threat_level}
      </span>
    </div>
  `;

  div.addEventListener('click', () => showAttackDetails(attack.id));

  return div;
}

// Get threat level CSS class
function getThreatClass(level) {
  if (level >= 9) return 'threat-critical';
  if (level >= 7) return 'threat-high';
  if (level >= 4) return 'threat-medium';
  return 'threat-low';
}

// Format timestamp
function formatTime(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleTimeString();
}

// Initialize map
function initMap() {
  state.map = L.map('map').setView([20, 0], 2);

  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© OpenStreetMap contributors'
  }).addTo(state.map);

  loadMapData();
}

// Load geographic data for map
async function loadMapData() {
  try {
    const response = await fetch('/api/analytics/geography');
    const data = await response.json();

    // Clear existing markers
    state.map.eachLayer(layer => {
      if (layer instanceof L.Marker) {
        state.map.removeLayer(layer);
      }
    });

    // Add markers for cities
    data.cities.forEach(city => {
      const marker = L.marker(city.coordinates)
        .addTo(state.map)
        .bindPopup(`
          <strong>${city.name}</strong><br>
          Attacks: ${city.count}
        `);
    });
  } catch (error) {
    console.error('Failed to load map data:', error);
  }
}

// Initialize charts
function initCharts() {
  // Timeline chart
  const timelineCtx = document.getElementById('timeline-chart').getContext('2d');
  state.charts.timeline = new Chart(timelineCtx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Attacks',
        data: [],
        borderColor: '#ff6b6b',
        backgroundColor: 'rgba(255, 107, 107, 0.1)',
        tension: 0.4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        y: { beginAtZero: true }
      }
    }
  });

  // Threat distribution chart
  const threatCtx = document.getElementById('threat-chart').getContext('2d');
  state.charts.threat = new Chart(threatCtx, {
    type: 'doughnut',
    data: {
      labels: ['Critical (9-10)', 'High (7-8)', 'Medium (4-6)', 'Low (0-3)'],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: ['#ff6b6b', '#ffa500', '#ffd700', '#4caf50']
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false
    }
  });

  // Service distribution chart
  const serviceCtx = document.getElementById('service-chart').getContext('2d');
  state.charts.service = new Chart(serviceCtx, {
    type: 'bar',
    data: {
      labels: ['HTTP', 'SSH', 'PostgreSQL', 'MySQL', 'FTP'],
      datasets: [{
        label: 'Attacks',
        data: [0, 0, 0, 0, 0],
        backgroundColor: '#42a5f5'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      }
    }
  });

  loadTimelineData();
}

// Update charts with new data
function updateCharts(stats) {
  // Threat distribution
  const threatData = [
    stats.by_threat_level.critical || 0,
    stats.by_threat_level.high || 0,
    stats.by_threat_level.medium || 0,
    stats.by_threat_level.low || 0
  ];
  state.charts.threat.data.datasets[0].data = threatData;
  state.charts.threat.update();

  // Service distribution
  const serviceData = [
    stats.by_service.HTTP || 0,
    stats.by_service.SSH || 0,
    stats.by_service.PostgreSQL || 0,
    stats.by_service.MySQL || 0,
    stats.by_service.FTP || 0
  ];
  state.charts.service.data.datasets[0].data = serviceData;
  state.charts.service.update();
}

// Load timeline data
async function loadTimelineData() {
  try {
    const response = await fetch('/api/analytics/timeline?interval=1h&period=24h');
    const data = await response.json();

    const labels = data.data.map(d => formatTime(d.timestamp));
    const values = data.data.map(d => d.count);

    state.charts.timeline.data.labels = labels;
    state.charts.timeline.data.datasets[0].data = values;
    state.charts.timeline.update();
  } catch (error) {
    console.error('Failed to load timeline:', error);
  }
}

// Connect to SSE stream
function connectSSE() {
  const eventSource = new EventSource('/api/attacks/stream');

  eventSource.addEventListener('attack', (e) => {
    const attack = JSON.parse(e.data);
    handleNewAttack(attack);
  });

  eventSource.addEventListener('heartbeat', (e) => {
    updateConnectionStatus('connected');
  });

  eventSource.onerror = (e) => {
    console.error('SSE error:', e);
    updateConnectionStatus('disconnected');
  };

  eventSource.addEventListener('open', () => {
    state.sseConnected = true;
    updateConnectionStatus('connected');
  });
}

// Handle new attack from SSE
function handleNewAttack(attack) {
  // Add to beginning of attacks array
  state.attacks.unshift(attack);
  if (state.attacks.length > 100) {
    state.attacks.pop();
  }

  // Add to attack feed
  const attackList = document.getElementById('attack-list');
  const item = createAttackItem(attack);
  item.classList.add('new');
  attackList.prepend(item);

  // Remove old items
  while (attackList.children.length > 50) {
    attackList.lastChild.remove();
  }

  // Update map if has geolocation
  if (attack.geolocation) {
    addAttackToMap(attack);
  }

  // Increment stats
  updateStatsIncremental(attack);
}

// Update connection status indicator
function updateConnectionStatus(status) {
  const indicator = document.getElementById('status-indicator');
  const text = document.getElementById('status-text');

  if (status === 'connected') {
    indicator.style.background = '#4caf50';
    text.textContent = 'Connected';
  } else {
    indicator.style.background = '#ff6b6b';
    text.textContent = 'Disconnected';
  }
}

// Add attack to map
function addAttackToMap(attack) {
  if (!attack.geolocation || !attack.geolocation.latitude) return;

  const marker = L.marker([
    attack.geolocation.latitude,
    attack.geolocation.longitude
  ]).addTo(state.map);

  marker.bindPopup(`
    <strong>${attack.source_ip}</strong><br>
    ${attack.geolocation.city}, ${attack.geolocation.country}<br>
    Service: ${attack.service_type}<br>
    Threat: ${attack.threat_level}
  `);

  // Auto-remove marker after 5 minutes
  setTimeout(() => {
    state.map.removeLayer(marker);
  }, 300000);
}

// Incrementally update stats
function updateStatsIncremental(attack) {
  // Update total attacks
  const totalEl = document.getElementById('total-attacks');
  totalEl.textContent = (parseInt(totalEl.textContent.replace(/,/g, '')) + 1).toLocaleString();

  // Update service-specific counter
  if (attack.service_type === 'HTTP') {
    const httpEl = document.getElementById('http-attacks');
    httpEl.textContent = (parseInt(httpEl.textContent.replace(/,/g, '')) + 1).toLocaleString();
  } else if (attack.service_type === 'SSH') {
    const sshEl = document.getElementById('ssh-attacks');
    sshEl.textContent = (parseInt(sshEl.textContent.replace(/,/g, '')) + 1).toLocaleString();
  }
}

// Show attack details modal
function showAttackDetails(attackId) {
  // TODO: Implement modal with detailed attack information
  console.log('Show details for attack:', attackId);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', init);
```

---

## 10.5 Implementation Sequence

### Day 1: Management API Foundation

**Morning (4 hours)**:
1. Create `blkbox/server/server.ts` with ManagementServer class
2. Implement basic HTTP server with Deno.serve
3. Implement health check endpoint (`/api/health`)
4. Implement status endpoint (`/api/status`)
5. Implement attacks endpoint (`/api/attacks`)
6. FFI integration for database queries
7. CORS configuration

**Afternoon (4 hours)**:
8. Implement analytics endpoints (`/api/analytics/summary`)
9. Implement timeline endpoint (`/api/analytics/timeline`)
10. Implement geography endpoint (`/api/analytics/geography`)
11. Implement attacker profiling endpoints
12. Test all API endpoints with curl/Postman

**Success Criteria**:
- All REST endpoints return valid JSON
- Database queries work via FFI
- CORS headers configured correctly
- API responds in < 100ms for most queries

### Day 2: SSE & Real-Time Updates

**Morning (4 hours)**:
1. Implement SSEManager class
2. Create SSE endpoint (`/api/attacks/stream`)
3. Integrate with EventPipeline for real-time events
4. Implement heartbeat mechanism
5. Client connection management
6. Test SSE with curl and browser

**Afternoon (4 hours)**:
7. Implement strike-back management endpoints
8. Implement pending approvals endpoint
9. Implement approval/denial endpoints
10. Integrate with StingerService
11. Test strike-back workflow

**Success Criteria**:
- SSE stream delivers attacks in real-time
- Multiple clients can connect simultaneously
- Heartbeat keeps connection alive
- Strike-back approvals work correctly

### Day 3: Dashboard UI

**Morning (4 hours)**:
1. Create HTML structure (`dashboard.html`)
2. Create CSS styling (`dashboard.css`)
3. Implement statistics cards
4. Implement attack feed UI
5. Static file serving

**Afternoon (4 hours)**:
6. Initialize JavaScript dashboard logic
7. Implement SSE client connection
8. Implement real-time attack feed updates
9. Implement stats card updates
10. Test in multiple browsers

**Success Criteria**:
- Dashboard loads and renders correctly
- Real-time updates appear in attack feed
- Statistics update automatically
- Responsive design works on mobile

### Day 4: Visualizations & Analytics

**Morning (4 hours)**:
1. Initialize Chart.js charts
2. Implement timeline chart
3. Implement threat distribution chart
4. Implement service distribution chart
5. Chart data loading from API

**Afternoon (4 hours)**:
6. Initialize Leaflet map
7. Implement geographic visualization
8. Add attack markers to map
9. Implement top attackers list
10. Interactive elements (click for details)

**Success Criteria**:
- All charts render correctly
- Map displays attack origins
- Charts update with new data
- Visualizations are performant

### Day 5: Export & Polish

**Morning (4 hours)**:
1. Implement JSON export
2. Implement CSV export
3. Implement PCAP export (if applicable)
4. Implement PDF report generation
5. File download handling

**Afternoon (4 hours)**:
6. Implement alert system (webhooks, email)
7. Implement honeypot control endpoints
8. Final testing and bug fixes
9. Performance optimization
10. Documentation

**Success Criteria**:
- All export formats work correctly
- Alerts can be configured
- Honeypots can be controlled via dashboard
- System is production-ready

---

## 10.6 File Structure

```
blkbox/
├── server/
│   ├── server.ts                   # Main ManagementServer class
│   ├── event-pipeline.ts           # (Already implemented)
│   ├── sse.ts                      # SSE manager
│   ├── export.ts                   # Export functionality
│   ├── alerts.ts                   # Alert system
│   ├── routes/
│   │   ├── mod.ts                  # Route definitions
│   │   ├── analytics.ts            # Analytics endpoints
│   │   ├── attackers.ts            # Attacker profiling
│   │   ├── strikeback.ts           # Strike-back management
│   │   └── honeypots.ts            # Honeypot control
│   └── static/
│       ├── dashboard.html          # Main dashboard page
│       ├── dashboard.css           # Dashboard styles
│       └── dashboard.js            # Dashboard logic
├── config/
│   ├── config.ts                   # (Already implemented)
│   └── mod.ts                      # (Already implemented)
└── main.ts                         # (Already implemented)
```

---

## 10.7 Success Criteria

### Phase 9: FTP Honeypot
- ✅ FTP honeypot starts successfully on port 21
- ✅ Accepts connections from standard FTP clients
- ✅ Authentication always succeeds
- ✅ Virtual filesystem displays realistic directories
- ✅ File downloads work (RETR command)
- ✅ File uploads are quarantined (STOR command)
- ✅ Uploaded files are hashed (SHA-256)
- ✅ Malware analysis hooks in place
- ✅ All FTP commands logged to database
- ✅ Threat levels calculated correctly
- ✅ Events generated for FFI layer
- ✅ Works with FileZilla, curl, and command-line FTP

### Phase 10: Management Dashboard
- ✅ Dashboard accessible via HTTP on port 9000
- ✅ Real-time attack feed updates via SSE
- ✅ Statistics cards show correct data
- ✅ Timeline chart displays 24h attack history
- ✅ Geographic map shows attack origins
- ✅ Threat distribution chart accurate
- ✅ Service distribution chart accurate
- ✅ Top attackers list populated
- ✅ Attack details clickable
- ✅ JSON export downloads correctly
- ✅ CSV export downloads correctly
- ✅ Strike-back approvals work (if enabled)
- ✅ Honeypot control endpoints functional
- ✅ Dashboard responsive on mobile devices
- ✅ Works in Chrome, Firefox, Safari

---

## Implementation Timeline

### Phase 9: FTP Honeypot
- **Day 1**: Core protocol implementation
- **Day 2**: Virtual filesystem and data connections
- **Day 3**: Upload quarantine and testing
- **Total**: 3 days

### Phase 10: Management Dashboard
- **Day 1**: Management API foundation
- **Day 2**: SSE and real-time updates
- **Day 3**: Dashboard UI
- **Day 4**: Visualizations and analytics
- **Day 5**: Export functionality and polish
- **Total**: 5 days

### Overall Timeline
- **Total Duration**: 8 days
- **Team Size**: 1 developer
- **Effort**: 64 hours

---

## Conclusion

This comprehensive plan provides detailed, step-by-step implementation guidance for completing Phases 9-10 of the BlkBox honeypot system. Following this plan will result in:

1. **Production-Ready FTP Honeypot**:
   - Full RFC 959 protocol compliance
   - Realistic virtual filesystem
   - Secure upload quarantine
   - Comprehensive malware analysis hooks
   - Session tracking and fingerprinting

2. **Professional Management Dashboard**:
   - Real-time attack visualization
   - Comprehensive analytics
   - Geographic mapping
   - Data export in multiple formats
   - Strike-back management
   - Honeypot control interface

3. **Complete BlkBox System**:
   - Multi-protocol honeypot (HTTP, SSH, FTP, databases)
   - Advanced tracking and correlation
   - Optional strike-back capabilities
   - Professional monitoring interface
   - Production-ready deployment

The BlkBox honeypot system will be feature-complete, thoroughly tested, and ready for deployment in real-world environments upon completion of these phases.

---

**Document Status**: ✅ Planning Complete
**Next Action**: Create todo list and begin implementation
**Last Updated**: 2025-12-25
