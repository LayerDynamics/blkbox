// Simplified SSH Honeypot Implementation
// Uses direct TCP handling to capture SSH login attempts

use super::traits::{HoneypotService, HoneypotStats, RequestContext};
use crate::ffi::types::{AttackEvent, ServiceType};
use crate::tracking::fingerprint::extract_ssh_algorithms;
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use std::time::Instant;

/// Simple SSH Honeypot Service
/// Captures SSH connection attempts and basic interactions
pub struct SshHoneypot {
    /// Port to listen on
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

impl SshHoneypot {
    /// Create a new SSH honeypot
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
impl HoneypotService for SshHoneypot {
    fn service_type(&self) -> ServiceType {
        ServiceType::SSH
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
        let state = Arc::new(SshHoneypotState {
            service_id: self.service_id,
            stats: Arc::clone(&self.stats),
            event_sender: self.event_sender.clone(),
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
                .expect("Failed to create SSH server runtime");

            rt.block_on(async move {
                println!("SSH server task started in dedicated thread");

                // Bind listener inside the dedicated runtime
                let addr = SocketAddr::from(([0, 0, 0, 0], port));
                let listener = match TcpListener::bind(addr).await {
                    Ok(l) => {
                        println!("SSH honeypot bound and listening on {}", addr);
                        l
                    }
                    Err(e) => {
                        eprintln!("Failed to bind SSH honeypot: {}", e);
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
                                    println!("Accepted SSH connection from {}", addr);
                                    let state_clone = Arc::clone(&state);
                                    tokio::spawn(async move {
                                        handle_ssh_connection(stream, addr, state_clone).await;
                                    });
                                }
                                Err(e) => {
                                    eprintln!("SSH accept error: {}", e);
                                    break;
                                }
                            }
                        }
                        _ = &mut shutdown_rx => {
                            println!("SSH server received shutdown signal");
                            break;
                        }
                    }
                }

                println!("SSH server task exiting");
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
                    eprintln!("SSH server thread panicked: {:?}", e);
                }
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to join SSH server thread: {}", e))?;
        }

        *running = false;
        println!("SSH honeypot on port {} stopped", self.port);

        Ok(())
    }

    fn is_running(&self) -> bool {
        false // TODO: Fix this properly
    }

    fn stats(&self) -> HoneypotStats {
        HoneypotStats::default() // TODO: Fix this properly
    }
}

/// Shared state for SSH honeypot
#[derive(Clone)]
struct SshHoneypotState {
    service_id: u32,
    stats: Arc<Mutex<HoneypotStats>>,
    event_sender: Option<mpsc::UnboundedSender<AttackEvent>>,
}

impl SshHoneypotState {
    /// Log an attack event
    async fn log_attack(&self, ctx: RequestContext) {
        // Update stats
        let mut stats = self.stats.lock().await;
        stats.total_connections += 1;
        stats.total_attacks += 1;

        // Send event to runtime
        if let Some(sender) = &self.event_sender {
            let event = ctx.to_attack_event();
            let _ = sender.send(event);
        }
    }
}

/// Handle an SSH connection
async fn handle_ssh_connection(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    state: Arc<SshHoneypotState>,
) {
    println!("SSH connection from {}", client_addr);

    // Send SSH protocol version (SSH-2.0)
    let server_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
    if let Err(e) = stream.write_all(server_version.as_bytes()).await {
        eprintln!("Failed to send SSH version: {}", e);
        return;
    }

    // Read client version
    let mut buffer = vec![0u8; 1024];

    let client_version = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read(&mut buffer),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => {
            let version = String::from_utf8_lossy(&buffer[..n]).to_string();
            println!("Client version from {}: {}", client_addr, version.trim());
            version
        }
        Ok(Ok(_)) => {
            println!("Client {} closed connection", client_addr);
            return;
        }
        Ok(Err(e)) => {
            eprintln!("Error reading from {}: {}", client_addr, e);
            return;
        }
        Err(_) => {
            println!("Timeout reading from {}", client_addr);
            return;
        }
    };

    // Try to extract SSH algorithms for HASSH fingerprinting
    let ssh_algorithms = extract_ssh_algorithms(&buffer[..buffer.len().min(1024)]);
    let ssh_fingerprint = ssh_algorithms.as_ref().map(|algorithms| algorithms.compute_hassh());

    // Generate comprehensive fingerprinting information
    let fingerprint_info = if let Some(algorithms) = &ssh_algorithms {
        let hassh_client = algorithms.compute_hassh();
        let hassh_server = algorithms.compute_hassh_server();
        let summary = algorithms.summary();

        format!(
            "\nHASSH (Client): {}\nHASSH Server: {}\nAlgorithms: {}",
            hassh_client,
            hassh_server,
            summary
        )
    } else {
        String::new()
    };

    // Log the SSH connection attempt
    let payload = format!(
        "SSH Connection Attempt\nClient Version: {}\nServer Version: {}{}",
        client_version.trim(),
        server_version.trim(),
        fingerprint_info
    );

    let threat_level = calculate_ssh_threat_level(&client_version);

    let ctx = RequestContext {
        client_addr,
        service_id: state.service_id,
        service_type: ServiceType::SSH,
        user_agent: Some(client_version.trim().to_string()),
        payload,
        threat_level,
        fingerprint: ssh_fingerprint,
        cf_metadata: None,
    };

    state.log_attack(ctx).await;

    // Keep connection open for a bit to seem realistic
    // In a real implementation, we'd handle the full SSH protocol
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Note: A full SSH implementation would continue with:
    // - Key exchange
    // - Authentication (password, public key)
    // - Channel opening
    // - Command execution
    // For now, we log the initial connection which is enough for basic honeypot functionality
}

/// Calculate threat level for SSH connections
fn calculate_ssh_threat_level(client_version: &str) -> u8 {
    let mut threat_level = 3u8; // Base level for SSH connections

    let version_lower = client_version.to_lowercase();

    // Scanning tools
    let scanner_signatures = [
        "libssh",        // Often used by scanners
        "paramiko",      // Python SSH library, common in attacks
        "golang",        // Go SSH library in scanners
        "scanner",
        "bot",
        "masscan",
    ];

    if scanner_signatures.iter().any(|sig| version_lower.contains(sig)) {
        threat_level += 4;
    }

    // Very old SSH versions (potential exploit attempts)
    if version_lower.contains("ssh-1.") {
        threat_level += 5;
    }

    // Unusual or custom SSH clients
    if !version_lower.contains("openssh")
        && !version_lower.contains("putty")
        && !version_lower.contains("bitvise") {
        threat_level += 2;
    }

    threat_level.min(10)
}
