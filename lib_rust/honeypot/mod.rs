// Honeypot service implementations
// Each protocol (HTTP, SSH, DB, FTP) implements the HoneypotService trait

pub mod traits;
pub mod http;
pub mod ssh;
pub mod ftp;

// Future honeypot modules
// pub mod postgres;
// pub mod mysql;
// pub mod mongodb;
