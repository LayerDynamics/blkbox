// FTP Honeypot Implementation
// Implements RFC 959 FTP protocol with virtual filesystem and upload quarantine

use super::traits::{HoneypotService, HoneypotStats, RequestContext};
use crate::ffi::types::{AttackEvent, ServiceType};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use std::time::Instant;
use std::path::PathBuf;

pub mod session;
pub mod filesystem;
pub mod data_channel;
pub mod commands;
pub mod quarantine;

use session::{FtpSession, FtpState};
use filesystem::VirtualFilesystem;
use commands::FtpCommand;

/// FTP Honeypot Service
/// Captures FTP connection attempts, file uploads, and interactions
pub struct FtpHoneypot {
    /// Port to listen on (typically 21)
    port: u16,

    /// Service ID assigned by runtime
    service_id: u32,

    /// Whether the service is currently running
    running: Arc<Mutex<bool>>,

    /// Statistics
    stats: Arc<Mutex<HoneypotStats>>,

    /// Start time for uptime calculation
    start_time: Option<Instant>,

    /// Channel to send attack events to runtime
    event_sender: Option<mpsc::UnboundedSender<AttackEvent>>,

    /// Server shutdown signal
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,

    /// Server join handle
    server_handle: Option<std::thread::JoinHandle<()>>,
}

impl FtpHoneypot {
    /// Create a new FTP honeypot
    pub fn new(port: u16, service_id: u32) -> Self {
        Self {
            port,
            service_id,
            running: Arc::new(Mutex::new(false)),
            stats: Arc::new(Mutex::new(HoneypotStats::default())),
            start_time: None,
            event_sender: None,
            shutdown_tx: None,
            server_handle: None,
        }
    }

    /// Set the event sender channel
    pub fn with_event_sender(mut self, sender: mpsc::UnboundedSender<AttackEvent>) -> Self {
        self.event_sender = Some(sender);
        self
    }

    /// Take the shutdown sender (can only be called once)
    pub fn take_shutdown_tx(&mut self) -> Option<tokio::sync::oneshot::Sender<()>> {
        self.shutdown_tx.take()
    }
}

#[async_trait]
impl HoneypotService for FtpHoneypot {
    fn service_type(&self) -> ServiceType {
        ServiceType::FTP
    }

    fn port(&self) -> u16 {
        self.port
    }

    async fn start(&mut self) -> Result<()> {
        let mut running = self.running.lock().await;
        if *running {
            return Ok(());
        }

        // Create shared state
        let state = Arc::new(FtpHoneypotState {
            service_id: self.service_id,
            stats: Arc::clone(&self.stats),
            event_sender: self.event_sender.clone(),
            filesystem: Arc::new(VirtualFilesystem::new()),
        });

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let port = self.port;

        // Spawn server in a dedicated thread with its own runtime
        let handle = std::thread::spawn(move || {
            // Create a new current-thread runtime for this server
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create FTP server runtime");

            rt.block_on(async move {
                println!("FTP server task started in dedicated thread");

                // Bind listener inside the dedicated runtime
                let addr = SocketAddr::from(([0, 0, 0, 0], port));
                let listener = match TcpListener::bind(addr).await {
                    Ok(l) => {
                        println!("FTP honeypot bound and listening on {}", addr);
                        l
                    }
                    Err(e) => {
                        eprintln!("Failed to bind FTP honeypot: {}", e);
                        return;
                    }
                };

                let mut shutdown_rx = shutdown_rx;

                // Run the server loop
                loop {
                    tokio::select! {
                        result = listener.accept() => {
                            match result {
                                Ok((stream, addr)) => {
                                    println!("Accepted FTP connection from {}", addr);
                                    let state_clone = Arc::clone(&state);
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_ftp_connection(stream, addr, state_clone).await {
                                            eprintln!("FTP connection error: {}", e);
                                        }
                                    });
                                }
                                Err(e) => {
                                    eprintln!("FTP accept error: {}", e);
                                    break;
                                }
                            }
                        }
                        _ = &mut shutdown_rx => {
                            println!("FTP server received shutdown signal");
                            break;
                        }
                    }
                }

                println!("FTP server task exiting");
            });
        });

        // Store the thread handle for proper cleanup
        self.server_handle = Some(handle);

        // Give the thread a moment to start and bind the listener
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        *running = true;
        self.start_time = Some(Instant::now());

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        let mut running = self.running.lock().await;
        if !*running {
            return Ok(());
        }

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Wait for the server thread to finish
        if let Some(handle) = self.server_handle.take() {
            // Join the thread in a blocking task to avoid blocking the async runtime
            tokio::task::spawn_blocking(move || {
                if let Err(e) = handle.join() {
                    eprintln!("FTP server thread panicked: {:?}", e);
                }
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to join FTP server thread: {}", e))?;
        }

        *running = false;
        println!("FTP honeypot on port {} stopped", self.port);

        Ok(())
    }

    fn is_running(&self) -> bool {
        false // TODO: Implement properly with Arc<Mutex<bool>> check
    }

    fn stats(&self) -> HoneypotStats {
        HoneypotStats::default() // TODO: Implement properly
    }
}

/// Shared state for FTP honeypot
#[derive(Clone)]
struct FtpHoneypotState {
    service_id: u32,
    stats: Arc<Mutex<HoneypotStats>>,
    event_sender: Option<mpsc::UnboundedSender<AttackEvent>>,
    filesystem: Arc<VirtualFilesystem>,
}

impl FtpHoneypotState {
    /// Log an attack event
    async fn log_attack(&self, ctx: RequestContext) {
        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.total_attacks += 1;
        }

        // Convert to AttackEvent and send
        if let Some(ref sender) = self.event_sender {
            let event = ctx.to_attack_event();
            let _ = sender.send(event);
        }
    }
}

/// Handle individual FTP connection
async fn handle_ftp_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    state: Arc<FtpHoneypotState>,
) -> Result<()> {
    // Create session
    let mut session = FtpSession::new(addr);

    // Send FTP banner: 220 Service ready
    let banner = "220 FTP Server ready\r\n";
    stream.write_all(banner.as_bytes()).await?;

    // Buffer for reading commands
    let mut buffer = vec![0u8; 4096];

    // Main command loop
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => {
                // Connection closed
                println!("FTP client {} disconnected", addr);
                break;
            }
            Ok(n) => {
                let data = &buffer[..n];
                let command_str = String::from_utf8_lossy(data).trim().to_string();

                // Parse command
                let response = match FtpCommand::parse(&command_str) {
                    Ok(cmd) => {
                        // Use command name for structured logging
                        let cmd_name = cmd.name();
                        println!("FTP command from {}: {} (raw: {})", addr, cmd_name, command_str);

                        // Track command using the canonical name
                        session.add_command(cmd_name);

                        // Handle the command
                        handle_ftp_command(cmd, &mut session, &state, &mut stream).await?
                    }
                    Err(e) => {
                        println!("FTP invalid command from {}: {} (error: {})", addr, command_str, e);
                        // Still track invalid commands for threat analysis
                        session.add_command(&command_str);
                        format!("500 Syntax error: {}\r\n", e)
                    }
                };

                // Send response
                stream.write_all(response.as_bytes()).await?;

                // Check if we should close connection
                if matches!(session.state, FtpState::Disconnected) {
                    break;
                }
            }
            Err(e) => {
                eprintln!("FTP read error: {}", e);
                break;
            }
        }
    }

    // Log the session as an attack event
    let threat_level = session.calculate_threat_level();
    let fingerprint = session.fingerprint_client();

    // Build detailed payload with command sequence
    let commands_str = if session.commands.len() <= 10 {
        // Show all commands if there are 10 or fewer
        session.commands.join(", ")
    } else {
        // Show first 5 and last 5 for longer sequences
        let first_five = &session.commands[..5];
        let last_five = &session.commands[session.commands.len() - 5..];
        format!("{} ... {} ({} total)",
            first_five.join(", "),
            last_five.join(", "),
            session.commands.len()
        )
    };

    let ctx = RequestContext {
        client_addr: addr,
        service_id: state.service_id,
        service_type: ServiceType::FTP,
        user_agent: Some(format!("FTP:{}:{}",
            session.username.as_deref().unwrap_or("unknown"),
            session.password.as_deref().unwrap_or("unknown")
        )),
        payload: format!(
            "FTP session [ID: {}]: {} commands [{}], {} bytes uploaded, {} bytes downloaded, {} files accessed",
            session.session_id,
            session.command_count,
            commands_str,
            session.bytes_uploaded,
            session.bytes_downloaded,
            session.files_accessed.len()
        ),
        threat_level,
        fingerprint,
        cf_metadata: None,
    };

    state.log_attack(ctx).await;

    Ok(())
}

/// Handle individual FTP command
async fn handle_ftp_command(
    command: FtpCommand,
    session: &mut FtpSession,
    state: &Arc<FtpHoneypotState>,
    _stream: &mut TcpStream,
) -> Result<String> {
    use FtpCommand::*;
    use std::path::PathBuf;

    let response = match command {
        User(username) => {
            session.username = Some(username.clone());
            session.state = FtpState::UserProvided;
            session.auth_attempts += 1;
            "331 Password required\r\n".to_string()
        }
        Pass(password) => {
            session.password = Some(password.clone());

            if matches!(session.state, FtpState::UserProvided) {
                session.state = FtpState::LoggedIn;
                "230 User logged in, proceed\r\n".to_string()
            } else {
                "503 Login with USER first\r\n".to_string()
            }
        }
        Quit => {
            session.state = FtpState::Disconnected;
            "221 Goodbye\r\n".to_string()
        }
        Syst => {
            "215 UNIX Type: L8\r\n".to_string()
        }
        Pwd => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }
            let path = session.current_dir.to_string_lossy();
            format!("257 \"{}\" is current directory\r\n", path)
        }
        Cwd(path) => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }

            // Resolve path (handle relative and absolute paths)
            let new_path = if path.starts_with('/') {
                PathBuf::from(&path)
            } else {
                session.current_dir.join(&path)
            };

            // Normalize path (resolve . and ..)
            let normalized = normalize_path(&new_path);

            // Check if directory exists in virtual filesystem
            if state.filesystem.exists(&normalized) && state.filesystem.is_directory(&normalized) {
                session.current_dir = normalized;
                "250 Directory successfully changed\r\n".to_string()
            } else {
                "550 Failed to change directory\r\n".to_string()
            }
        }
        Cdup => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }

            // Go up one directory
            if let Some(parent) = session.current_dir.parent() {
                session.current_dir = if parent.as_os_str().is_empty() {
                    PathBuf::from("/")
                } else {
                    parent.to_path_buf()
                };
                "250 Directory successfully changed\r\n".to_string()
            } else {
                // Already at root
                session.current_dir = PathBuf::from("/");
                "250 Directory successfully changed\r\n".to_string()
            }
        }
        Pasv => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }

            // Enter passive mode
            match session.data_channel.enter_passive_mode().await {
                Ok(addr) => {
                    use data_channel::format_pasv_response;
                    let formatted = format_pasv_response(addr);

                    // Log the passive port for debugging/monitoring
                    if let Some(port) = session.data_channel.passive_port() {
                        println!("FTP client {} entered passive mode on port {}",
                            session.client_addr, port);
                    }

                    format!("227 Entering Passive Mode ({})\r\n", formatted)
                }
                Err(e) => {
                    eprintln!("Failed to enter passive mode: {}", e);
                    "425 Cannot open data connection\r\n".to_string()
                }
            }
        }
        Port(addr_str) => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }

            // Parse PORT address
            use data_channel::parse_port_address;
            match parse_port_address(&addr_str) {
                Ok(addr) => {
                    match session.data_channel.enter_active_mode(addr) {
                        Ok(_) => "200 PORT command successful\r\n".to_string(),
                        Err(e) => {
                            eprintln!("Failed to enter active mode: {}", e);
                            "425 Cannot open data connection\r\n".to_string()
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse PORT address: {}", e);
                    "501 Syntax error in parameters\r\n".to_string()
                }
            }
        }
        List(path_arg) => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }

            // Determine path to list
            let list_path = if let Some(ref p) = path_arg {
                if p.starts_with('/') {
                    PathBuf::from(p)
                } else {
                    session.current_dir.join(p)
                }
            } else {
                session.current_dir.clone()
            };

            let normalized = normalize_path(&list_path);

            // Check if path exists
            if !state.filesystem.exists(&normalized) {
                return Ok("550 No such file or directory\r\n".to_string());
            }

            // Get directory listing
            let entries = state.filesystem.list_directory(&normalized);

            // Format listing in Unix ls -l format
            let mut listing = String::new();
            for entry in entries {
                let line = format!(
                    "{} 1 {} {} {:>12} {} {}\r\n",
                    entry.permissions,
                    entry.owner,
                    entry.group,
                    entry.size,
                    entry.modified,
                    entry.name
                );
                listing.push_str(&line);
            }

            // Send listing over data channel
            match session.data_channel.send_data(listing.as_bytes()).await {
                Ok(_) => {
                    // Reset data channel after successful transfer
                    session.data_channel.reset();
                    "150 Opening data connection\r\n226 Transfer complete\r\n".to_string()
                }
                Err(e) => {
                    eprintln!("Failed to send directory listing: {}", e);
                    // Reset data channel on error too
                    session.data_channel.reset();
                    "425 Cannot open data connection\r\n".to_string()
                }
            }
        }
        Nlst(path_arg) => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }

            // Determine path to list
            let list_path = if let Some(ref p) = path_arg {
                if p.starts_with('/') {
                    PathBuf::from(p)
                } else {
                    session.current_dir.join(p)
                }
            } else {
                session.current_dir.clone()
            };

            let normalized = normalize_path(&list_path);

            // Check if path exists
            if !state.filesystem.exists(&normalized) {
                return Ok("550 No such file or directory\r\n".to_string());
            }

            // Get directory listing (names only)
            let entries = state.filesystem.list_directory(&normalized);
            let mut listing = String::new();
            for entry in entries {
                listing.push_str(&entry.name);
                listing.push_str("\r\n");
            }

            // Send listing over data channel
            match session.data_channel.send_data(listing.as_bytes()).await {
                Ok(_) => {
                    // Reset data channel after successful transfer
                    session.data_channel.reset();
                    "150 Opening data connection\r\n226 Transfer complete\r\n".to_string()
                }
                Err(e) => {
                    eprintln!("Failed to send directory listing: {}", e);
                    // Reset data channel on error too
                    session.data_channel.reset();
                    "425 Cannot open data connection\r\n".to_string()
                }
            }
        }
        Retr(filename) => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }

            // Resolve file path
            let file_path = if filename.starts_with('/') {
                PathBuf::from(&filename)
            } else {
                session.current_dir.join(&filename)
            };

            let normalized = normalize_path(&file_path);

            // Track file access
            session.access_file(&normalized.to_string_lossy());

            // Check if file exists and is not a directory
            if !state.filesystem.exists(&normalized) {
                return Ok("550 File not found\r\n".to_string());
            }

            if state.filesystem.is_directory(&normalized) {
                return Ok("550 Is a directory\r\n".to_string());
            }

            // Get file content
            match state.filesystem.get_file_content(&normalized) {
                Some(content) => {
                    let size = content.len() as u64;
                    session.bytes_downloaded += size;

                    // Send file over data channel
                    match session.data_channel.send_data(&content).await {
                        Ok(_) => {
                            // Reset data channel after successful transfer
                            session.data_channel.reset();
                            format!("150 Opening data connection\r\n226 Transfer complete ({} bytes)\r\n", size)
                        }
                        Err(e) => {
                            eprintln!("Failed to send file: {}", e);
                            // Reset data channel on error too
                            session.data_channel.reset();
                            "425 Cannot open data connection\r\n".to_string()
                        }
                    }
                }
                None => {
                    "550 Failed to read file\r\n".to_string()
                }
            }
        }
        Stor(filename) => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }

            // Receive file data (limit to 100MB)
            const MAX_UPLOAD_SIZE: usize = 100 * 1024 * 1024;

            match session.data_channel.receive_data(MAX_UPLOAD_SIZE).await {
                Ok(data) => {
                    let size = data.len() as u64;
                    session.bytes_uploaded += size;

                    // Check if executable
                    use quarantine::is_executable_file;
                    if is_executable_file(&data, &filename) {
                        session.uploaded_executables = true;
                    }

                    // Quarantine the file
                    use quarantine::QuarantineManager;
                    let quarantine_dir = std::path::PathBuf::from("./quarantine");
                    match QuarantineManager::new(quarantine_dir) {
                        Ok(qm) => {
                            let client_ip = session.client_addr.ip().to_string();
                            let username = session.username.as_deref().unwrap_or("anonymous");

                            match qm.quarantine_file(&filename, &data, &client_ip, username) {
                                Ok(quarantined) => {
                                    println!(
                                        "Quarantined upload: {} ({} bytes, SHA256: {}, malware_score: {})",
                                        filename, size, quarantined.sha256, quarantined.malware_score
                                    );

                                    // Reset data channel after successful transfer
                                    session.data_channel.reset();
                                    format!("150 Opening data connection\r\n226 Transfer complete ({} bytes)\r\n", size)
                                }
                                Err(e) => {
                                    eprintln!("Failed to quarantine file: {}", e);
                                    // Reset data channel on error too
                                    session.data_channel.reset();
                                    "450 Requested file action not taken\r\n".to_string()
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to create quarantine manager: {}", e);
                            // Reset data channel on error
                            session.data_channel.reset();
                            "450 Requested file action not taken\r\n".to_string()
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to receive upload: {}", e);
                    // Reset data channel on error
                    session.data_channel.reset();
                    "425 Cannot open data connection\r\n".to_string()
                }
            }
        }
        Size(filename) => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }

            // Resolve file path
            let file_path = if filename.starts_with('/') {
                PathBuf::from(&filename)
            } else {
                session.current_dir.join(&filename)
            };

            let normalized = normalize_path(&file_path);

            // Get file info
            match state.filesystem.get_file(&normalized) {
                Some(file) if !file.is_directory => {
                    format!("213 {}\r\n", file.size)
                }
                _ => "550 File not found\r\n".to_string()
            }
        }
        Noop => {
            "200 OK\r\n".to_string()
        }
        Feat => {
            "211-Features:\r\n SIZE\r\n MDTM\r\n PASV\r\n211 End\r\n".to_string()
        }
        Type(type_code) => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }

            match type_code.as_str() {
                "A" => {
                    session.binary_mode = false;
                    "200 Type set to ASCII\r\n".to_string()
                }
                "I" => {
                    session.binary_mode = true;
                    "200 Type set to Binary\r\n".to_string()
                }
                _ => "504 Type not implemented\r\n".to_string()
            }
        }
        Rnfr(from_name) => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }

            // Store the source filename for the rename operation
            session.rename_from = Some(from_name.clone());
            session.state = FtpState::Renaming;

            format!("350 Ready for RNTO\r\n")
        }
        Rnto(to_name) => {
            if !matches!(session.state, FtpState::Renaming) {
                return Ok("503 RNFR required first\r\n".to_string());
            }

            // Get the source filename
            let from_name = session.rename_from.take()
                .ok_or_else(|| anyhow!("No rename source set"))?;

            // Resolve paths
            let from_path = if from_name.starts_with('/') {
                PathBuf::from(&from_name)
            } else {
                session.current_dir.join(&from_name)
            };

            let to_path = if to_name.starts_with('/') {
                PathBuf::from(&to_name)
            } else {
                session.current_dir.join(&to_name)
            };

            let normalized_from = normalize_path(&from_path);
            let normalized_to = normalize_path(&to_path);

            // Check if source exists
            if !state.filesystem.exists(&normalized_from) {
                session.state = FtpState::LoggedIn;
                return Ok("550 Source file not found\r\n".to_string());
            }

            // Track the operation
            session.access_file(&normalized_from.to_string_lossy());

            // In a real implementation, we would perform the rename in the virtual filesystem
            // For now, just acknowledge the attempt
            session.state = FtpState::LoggedIn;
            format!("250 Rename from {} to {} successful\r\n",
                normalized_from.to_string_lossy(),
                normalized_to.to_string_lossy())
        }
        Dele(filename) => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }

            // Resolve file path
            let file_path = if filename.starts_with('/') {
                PathBuf::from(&filename)
            } else {
                session.current_dir.join(&filename)
            };

            let normalized = normalize_path(&file_path);

            // Track the operation
            session.access_file(&normalized.to_string_lossy());

            // Check if file exists
            if state.filesystem.exists(&normalized) {
                format!("250 File {} deleted\r\n", normalized.to_string_lossy())
            } else {
                "550 File not found\r\n".to_string()
            }
        }
        Mkd(dirname) => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }

            // Resolve directory path
            let dir_path = if dirname.starts_with('/') {
                PathBuf::from(&dirname)
            } else {
                session.current_dir.join(&dirname)
            };

            let normalized = normalize_path(&dir_path);

            // Track the operation
            session.access_file(&normalized.to_string_lossy());

            format!("257 \"{}\" created\r\n", normalized.to_string_lossy())
        }
        Rmd(dirname) => {
            if !matches!(session.state, FtpState::LoggedIn) {
                return Ok("530 Not logged in\r\n".to_string());
            }

            // Resolve directory path
            let dir_path = if dirname.starts_with('/') {
                PathBuf::from(&dirname)
            } else {
                session.current_dir.join(&dirname)
            };

            let normalized = normalize_path(&dir_path);

            // Track the operation
            session.access_file(&normalized.to_string_lossy());

            format!("250 \"{}\" removed\r\n", normalized.to_string_lossy())
        }
        Mode(_) | Stru(_) => {
            // These commands are rarely used
            "200 OK\r\n".to_string()
        }
        _ => {
            "502 Command not implemented\r\n".to_string()
        }
    };

    Ok(response)
}

/// Normalize a path by resolving . and .. components
fn normalize_path(path: &std::path::Path) -> PathBuf {
    let mut components = Vec::new();

    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => {
                components.push(part);
            }
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::RootDir => {
                components.clear();
            }
            _ => {}
        }
    }

    if components.is_empty() {
        PathBuf::from("/")
    } else {
        let mut result = PathBuf::from("/");
        for comp in components {
            result.push(comp);
        }
        result
    }
}
