// FTP Data Channel Management
// Handles PASV (passive) and PORT (active) data connections for file transfers

use anyhow::{Result, anyhow};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Data channel mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataChannelMode {
    /// Passive mode - server listens, client connects
    Passive,
    /// Active mode - client listens, server connects
    Active,
}

/// Data channel manager
/// Handles FTP data connections for file transfers and directory listings
pub struct DataChannelManager {
    mode: Option<DataChannelMode>,
    passive_listener: Option<TcpListener>,
    passive_port: Option<u16>,
    active_addr: Option<SocketAddr>,
}

impl DataChannelManager {
    /// Create a new data channel manager
    pub fn new() -> Self {
        Self {
            mode: None,
            passive_listener: None,
            passive_port: None,
            active_addr: None,
        }
    }

    /// Enter passive mode (PASV command)
    /// Binds a listener on an ephemeral port and returns the address
    pub async fn enter_passive_mode(&mut self) -> Result<SocketAddr> {
        // Bind to random port in passive range (49152-65535)
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let addr = listener.local_addr()?;

        self.mode = Some(DataChannelMode::Passive);
        self.passive_port = Some(addr.port());
        self.passive_listener = Some(listener);

        Ok(addr)
    }

    /// Enter active mode (PORT command)
    /// Stores the client's address for later connection
    pub fn enter_active_mode(&mut self, client_addr: SocketAddr) -> Result<()> {
        self.mode = Some(DataChannelMode::Active);
        self.active_addr = Some(client_addr);
        self.passive_listener = None;
        self.passive_port = None;

        Ok(())
    }

    /// Accept a data connection
    /// In passive mode, waits for client to connect
    /// In active mode, connects to client
    pub async fn accept(&mut self) -> Result<tokio::net::TcpStream> {
        match self.mode {
            Some(DataChannelMode::Passive) => {
                if let Some(listener) = self.passive_listener.take() {
                    let (stream, _addr) = listener.accept().await?;
                    Ok(stream)
                } else {
                    Err(anyhow!("No passive listener available"))
                }
            }
            Some(DataChannelMode::Active) => {
                if let Some(addr) = self.active_addr {
                    let stream = tokio::net::TcpStream::connect(addr).await?;
                    Ok(stream)
                } else {
                    Err(anyhow!("No active address set"))
                }
            }
            None => {
                Err(anyhow!("No data channel mode set"))
            }
        }
    }

    /// Send data over the data channel
    pub async fn send_data(&mut self, data: &[u8]) -> Result<()> {
        let mut stream = self.accept().await?;
        stream.write_all(data).await?;
        stream.shutdown().await?;
        Ok(())
    }

    /// Receive data from the data channel
    pub async fn receive_data(&mut self, max_size: usize) -> Result<Vec<u8>> {
        let mut stream = self.accept().await?;
        let mut buffer = Vec::new();

        // Read with size limit to prevent memory exhaustion
        let mut chunk = vec![0u8; 8192];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }

            if buffer.len() + n > max_size {
                return Err(anyhow!("Upload size exceeds limit"));
            }

            buffer.extend_from_slice(&chunk[..n]);
        }

        Ok(buffer)
    }

    /// Get the passive port
    pub fn passive_port(&self) -> Option<u16> {
        self.passive_port
    }

    /// Reset the data channel
    pub fn reset(&mut self) {
        self.mode = None;
        self.passive_listener = None;
        self.passive_port = None;
        self.active_addr = None;
    }
}

impl Default for DataChannelManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse PORT command argument
/// Format: h1,h2,h3,h4,p1,p2 where IP = h1.h2.h3.h4 and port = p1*256+p2
pub fn parse_port_address(arg: &str) -> Result<SocketAddr> {
    let parts: Vec<&str> = arg.split(',').collect();
    if parts.len() != 6 {
        return Err(anyhow!("Invalid PORT format"));
    }

    let octets: Result<Vec<u8>> = parts[0..4]
        .iter()
        .map(|s| s.parse::<u8>().map_err(|_| anyhow!("Invalid IP octet")))
        .collect();
    let octets = octets?;

    let p1 = parts[4].parse::<u16>().map_err(|_| anyhow!("Invalid port"))?;
    let p2 = parts[5].parse::<u16>().map_err(|_| anyhow!("Invalid port"))?;
    let port = (p1 * 256) + p2;

    let addr = SocketAddr::from(([octets[0], octets[1], octets[2], octets[3]], port));
    Ok(addr)
}

/// Format address for PASV response
/// Returns: h1,h2,h3,h4,p1,p2
pub fn format_pasv_response(addr: SocketAddr) -> String {
    let ip = match addr {
        SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
        SocketAddr::V6(_) => vec![127, 0, 0, 1], // Fallback to localhost for IPv6
    };

    let port = addr.port();
    let p1 = port / 256;
    let p2 = port % 256;

    format!("{},{},{},{},{},{}", ip[0], ip[1], ip[2], ip[3], p1, p2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_address() {
        let addr = parse_port_address("192,168,1,100,19,136").unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.100");
        assert_eq!(addr.port(), 5000); // 19*256 + 136 = 5000
    }

    #[test]
    fn test_format_pasv_response() {
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let formatted = format_pasv_response(addr);
        assert_eq!(formatted, "192,168,1,1,19,136"); // 5000 = 19*256 + 136
    }

    #[tokio::test]
    async fn test_passive_port() {
        let mut manager = DataChannelManager::new();

        // Initially no port
        assert_eq!(manager.passive_port(), None);

        // Enter passive mode
        let _addr = manager.enter_passive_mode().await.unwrap();

        // Should have a port now
        assert!(manager.passive_port().is_some());
        let port = manager.passive_port().unwrap();
        assert!(port > 0);
    }

    #[tokio::test]
    async fn test_reset() {
        let mut manager = DataChannelManager::new();

        // Enter passive mode
        let _addr = manager.enter_passive_mode().await.unwrap();
        assert!(manager.passive_port().is_some());

        // Reset should clear state
        manager.reset();
        assert_eq!(manager.passive_port(), None);
    }
}
