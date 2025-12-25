// FTP Upload Quarantine System
// Safely stores uploaded files with malware analysis and hashing

use anyhow::{Result, Context as AnyhowContext};
use std::path::{Path, PathBuf};
use std::fs;
use std::io::Write;
use sha2::{Sha256, Digest};
use chrono::Utc;
use uuid::Uuid;

/// Quarantined file metadata
#[derive(Debug, Clone)]
pub struct QuarantinedFile {
    /// Unique quarantine ID
    pub id: String,

    /// Original filename from FTP client
    pub original_name: String,

    /// Path in quarantine directory
    pub quarantine_path: PathBuf,

    /// File size in bytes
    pub size: u64,

    /// SHA-256 hash
    pub sha256: String,

    /// MD5 hash
    pub md5: String,

    /// Client IP address
    pub client_ip: String,

    /// FTP username
    pub username: String,

    /// Upload timestamp
    pub timestamp: String,

    /// Detected file type
    pub file_type: String,

    /// Threat indicators
    pub is_executable: bool,
    pub is_script: bool,
    pub is_archive: bool,

    /// Malware analysis result
    pub malware_score: u8, // 0-10
}

/// Quarantine manager
/// Handles secure storage and analysis of uploaded files
pub struct QuarantineManager {
    quarantine_dir: PathBuf,
}

impl QuarantineManager {
    /// Create a new quarantine manager
    pub fn new<P: AsRef<Path>>(quarantine_dir: P) -> Result<Self> {
        let dir = quarantine_dir.as_ref().to_path_buf();

        // Create quarantine directory if it doesn't exist
        fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create quarantine directory: {:?}", dir))?;

        Ok(Self {
            quarantine_dir: dir,
        })
    }

    /// Quarantine an uploaded file
    pub fn quarantine_file(
        &self,
        original_name: &str,
        data: &[u8],
        client_ip: &str,
        username: &str,
    ) -> Result<QuarantinedFile> {
        // Generate unique ID
        let id = Uuid::new_v4().to_string();

        // Calculate hashes
        let sha256 = hex::encode(Sha256::digest(data));
        let md5 = format!("{:x}", md5::compute(data));

        // Create quarantine subdirectory by date
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let subdir = self.quarantine_dir.join(&date);
        fs::create_dir_all(&subdir)?;

        // Save file with UUID filename
        let quarantine_path = subdir.join(&id);
        let mut file = fs::File::create(&quarantine_path)?;
        file.write_all(data)?;
        file.sync_all()?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&quarantine_path)?.permissions();
            perms.set_mode(0o400); // Read-only for owner
            fs::set_permissions(&quarantine_path, perms)?;
        }

        // Detect file type and threat indicators
        let file_type = detect_file_type(data, original_name);
        let is_executable = is_executable_file(data, original_name);
        let is_script = is_script_file(data, original_name);
        let is_archive = is_archive_file(original_name);

        // Calculate malware score
        let malware_score = calculate_malware_score(data, original_name, is_executable, is_script);

        Ok(QuarantinedFile {
            id,
            original_name: original_name.to_string(),
            quarantine_path,
            size: data.len() as u64,
            sha256,
            md5,
            client_ip: client_ip.to_string(),
            username: username.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            file_type,
            is_executable,
            is_script,
            is_archive,
            malware_score,
        })
    }

    /// Get quarantine directory path
    pub fn quarantine_dir(&self) -> &Path {
        &self.quarantine_dir
    }
}

/// Detect file type from magic bytes and filename
fn detect_file_type(data: &[u8], filename: &str) -> String {
    if data.is_empty() {
        return "empty".to_string();
    }

    // Check magic bytes
    if data.len() >= 4 {
        match &data[0..4] {
            [0x7f, 0x45, 0x4c, 0x46] => return "ELF executable".to_string(),
            [0x4d, 0x5a, ..] => return "PE executable".to_string(),
            [0x50, 0x4b, 0x03, 0x04] => return "ZIP archive".to_string(),
            [0x1f, 0x8b, ..] => return "GZIP archive".to_string(),
            _ => {}
        }
    }

    if data.len() >= 2 {
        if &data[0..2] == b"#!" {
            return "Shell script".to_string();
        }
    }

    // Check by extension
    if let Some(ext) = Path::new(filename).extension() {
        match ext.to_string_lossy().to_lowercase().as_str() {
            "exe" | "dll" | "sys" => return "Windows executable".to_string(),
            "sh" | "bash" | "zsh" => return "Shell script".to_string(),
            "py" | "pyc" => return "Python script".to_string(),
            "js" => return "JavaScript".to_string(),
            "php" => return "PHP script".to_string(),
            "jar" => return "Java archive".to_string(),
            "zip" | "tar" | "gz" | "bz2" | "7z" | "rar" => return "Archive".to_string(),
            _ => {}
        }
    }

    // Check if text
    if data.iter().take(512).all(|&b| b.is_ascii() || b == b'\n' || b == b'\r' || b == b'\t') {
        return "Text file".to_string();
    }

    "Binary file".to_string()
}

/// Check if file is executable
pub fn is_executable_file(data: &[u8], filename: &str) -> bool {
    // ELF magic
    if data.len() >= 4 && &data[0..4] == b"\x7fELF" {
        return true;
    }

    // PE magic (MZ)
    if data.len() >= 2 && &data[0..2] == b"MZ" {
        return true;
    }

    // Mach-O magic (macOS)
    if data.len() >= 4 {
        if matches!(&data[0..4], [0xfe, 0xed, 0xfa, 0xce] | [0xce, 0xfa, 0xed, 0xfe]) {
            return true;
        }
    }

    // Check extension
    if let Some(ext) = Path::new(filename).extension() {
        matches!(
            ext.to_string_lossy().to_lowercase().as_str(),
            "exe" | "dll" | "sys" | "so" | "dylib" | "bin"
        )
    } else {
        false
    }
}

/// Check if file is a script
fn is_script_file(data: &[u8], filename: &str) -> bool {
    // Shebang
    if data.len() >= 2 && &data[0..2] == b"#!" {
        return true;
    }

    // Check extension
    if let Some(ext) = Path::new(filename).extension() {
        matches!(
            ext.to_string_lossy().to_lowercase().as_str(),
            "sh" | "bash" | "zsh" | "py" | "rb" | "pl" | "php" | "js" | "ps1" | "bat" | "cmd"
        )
    } else {
        false
    }
}

/// Check if file is an archive
fn is_archive_file(filename: &str) -> bool {
    if let Some(ext) = Path::new(filename).extension() {
        matches!(
            ext.to_string_lossy().to_lowercase().as_str(),
            "zip" | "tar" | "gz" | "bz2" | "7z" | "rar" | "jar" | "tgz" | "tbz2"
        )
    } else {
        false
    }
}

/// Calculate malware score (0-10)
fn calculate_malware_score(data: &[u8], filename: &str, is_executable: bool, is_script: bool) -> u8 {
    let mut score = 0u8;

    // Base score for any upload
    score += 2;

    // Executable files
    if is_executable {
        score += 5;
    }

    // Scripts
    if is_script {
        score += 3;
    }

    // Suspicious extensions
    let suspicious_exts = ["exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "jar"];
    if let Some(ext) = Path::new(filename).extension() {
        if suspicious_exts.contains(&ext.to_string_lossy().to_lowercase().as_str()) {
            score += 2;
        }
    }

    // Suspicious patterns in content (basic heuristics)
    let content_str = String::from_utf8_lossy(data);
    let suspicious_patterns = [
        "eval(", "exec(", "system(", "shell_exec",
        "cmd.exe", "powershell", "/bin/sh", "/bin/bash",
        "wget ", "curl ", "nc -", "netcat",
        "reverse_tcp", "meterpreter", "metasploit",
    ];

    for pattern in &suspicious_patterns {
        if content_str.contains(pattern) {
            score += 1;
            break;
        }
    }

    // Obfuscated content (high entropy or unusual character distribution)
    if is_likely_obfuscated(data) {
        score += 2;
    }

    score.min(10)
}

/// Basic obfuscation detection using entropy and character analysis
fn is_likely_obfuscated(data: &[u8]) -> bool {
    if data.len() < 100 {
        return false;
    }

    // Sample first 512 bytes
    let sample = &data[..data.len().min(512)];

    // Count character classes
    let mut non_printable = 0;

    for &byte in sample {
        if byte < 32 && byte != b'\n' && byte != b'\r' && byte != b'\t' {
            non_printable += 1;
        }
    }

    // High ratio of non-printable characters suggests obfuscation or binary
    non_printable as f32 / sample.len() as f32 > 0.3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_elf() {
        let elf_data = b"\x7fELF\x00\x00\x00\x00";
        assert_eq!(detect_file_type(elf_data, "test"), "ELF executable");
    }

    #[test]
    fn test_detect_script() {
        let script_data = b"#!/bin/bash\necho hello";
        assert_eq!(detect_file_type(script_data, "test.sh"), "Shell script");
    }

    #[test]
    fn test_is_executable() {
        let elf_data = b"\x7fELF\x00\x00\x00\x00";
        assert!(is_executable_file(elf_data, "test"));

        let text_data = b"Hello World";
        assert!(!is_executable_file(text_data, "test.txt"));
    }

    #[test]
    fn test_malware_score() {
        let exe_data = b"MZ\x00\x00"; // PE header
        let score = calculate_malware_score(exe_data, "malware.exe", true, false);
        assert!(score >= 7); // Should be high for executable

        let text_data = b"Hello World";
        let score = calculate_malware_score(text_data, "hello.txt", false, false);
        assert!(score <= 3); // Should be low for plain text
    }
}
