// Virtual Filesystem for FTP Honeypot
// Provides realistic directory structure with bait files

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use chrono::Utc;

/// Virtual Filesystem
/// Simulates a realistic FTP server directory structure
pub struct VirtualFilesystem {
    files: HashMap<PathBuf, VirtualFile>,
}

/// Virtual File Entry
pub struct VirtualFile {
    pub name: String,
    pub is_directory: bool,
    pub size: u64,
    pub permissions: String,
    pub owner: String,
    pub group: String,
    pub modified: String,
    pub content: FileContent,
}

/// File Content Types
pub enum FileContent {
    /// Static embedded content
    Static(&'static [u8]),
    /// Dynamically generated content
    Generated(Box<dyn Fn() -> Vec<u8> + Send + Sync>),
    /// Empty file
    Empty,
    /// Large fake file (size only, no content)
    Large(u64),
}

impl VirtualFilesystem {
    /// Create a new virtual filesystem with realistic structure
    pub fn new() -> Self {
        let mut fs = Self {
            files: HashMap::new(),
        };

        fs.initialize_structure();
        fs
    }

    /// Initialize the directory structure
    fn initialize_structure(&mut self) {
        // Root directory
        self.add_directory("/", "root", "root", "drwxr-xr-x");

        // /pub - Public directory
        self.add_directory("/pub", "ftp", "ftp", "drwxr-xr-x");
        self.add_file("/pub/README.txt", "ftp", "ftp", "-rw-r--r--",
            FileContent::Static(b"Welcome to our FTP server!\n\nPlease upload files to the /pub/incoming directory.\n"));
        self.add_directory("/pub/incoming", "ftp", "ftp", "drwxrwxrwx");
        self.add_directory("/pub/software", "ftp", "ftp", "drwxr-xr-x");
        self.add_directory("/pub/documents", "ftp", "ftp", "drwxr-xr-x");

        // /home - User directories
        self.add_directory("/home", "root", "root", "drwxr-xr-x");
        self.add_directory("/home/admin", "admin", "admin", "drwx------");

        // /home/admin/.bash_history - BAIT
        self.add_file("/home/admin/.bash_history", "admin", "admin", "-rw-------",
            FileContent::Generated(Box::new(|| {
                b"mysql -u root -p\n\
cd /var/www/html\n\
vim .env\n\
mysqldump -u root -p prod_db > backup/database.sql\n\
gzip backup/database.sql\n\
tar -czf backup/config.tar.gz /etc/app/\n\
cat /etc/passwd\n\
netstat -tulpn\n".to_vec()
            }))
        );

        // /home/admin/.ssh - SSH keys BAIT
        self.add_directory("/home/admin/.ssh", "admin", "admin", "drwx------");
        self.add_file("/home/admin/.ssh/authorized_keys", "admin", "admin", "-rw-------",
            FileContent::Generated(Box::new(|| {
                b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... admin@server\n\
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD... backup@server\n".to_vec()
            }))
        );

        // /home/admin/backup - CRITICAL BAIT
        self.add_directory("/home/admin/backup", "admin", "admin", "drwx------");
        self.add_file("/home/admin/backup/database.sql.gz", "admin", "admin", "-rw-------",
            FileContent::Large(15728640) // 15MB fake SQL dump
        );
        self.add_file("/home/admin/backup/config.tar.gz", "admin", "admin", "-rw-------",
            FileContent::Large(5242880) // 5MB fake config archive
        );

        // /var - System files
        self.add_directory("/var", "root", "root", "drwxr-xr-x");
        self.add_directory("/var/log", "root", "root", "drwxr-xr-x");
        self.add_file("/var/log/auth.log", "root", "root", "-rw-r-----",
            FileContent::Generated(Box::new(|| {
                let now = Utc::now().format("%b %d %H:%M:%S");
                format!("{} server sshd[1234]: Accepted password for admin from 192.168.1.100 port 54321\n", now).into_bytes()
            }))
        );

        // /var/www/html - Web root
        self.add_directory("/var/www", "root", "root", "drwxr-xr-x");
        self.add_directory("/var/www/html", "www-data", "www-data", "drwxr-xr-x");

        // /.env - CRITICAL BAIT
        self.add_file("/var/www/html/.env", "www-data", "www-data", "-rw-r-----",
            FileContent::Generated(Box::new(|| {
                b"APP_NAME=ProductionApp\n\
APP_ENV=production\n\
DB_HOST=10.0.1.25\n\
DB_DATABASE=prod_db\n\
DB_USERNAME=db_admin\n\
DB_PASSWORD=Pr0d!Secret@2024\n\n\
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\
STRIPE_KEY=sk_test_FakeHoneypotKey9876543210\n".to_vec()
            }))
        );

        // /etc - System configuration
        self.add_directory("/etc", "root", "root", "drwxr-xr-x");
        self.add_file("/etc/passwd", "root", "root", "-rw-r--r--",
            FileContent::Generated(Box::new(|| {
                b"root:x:0:0:root:/root:/bin/bash\n\
admin:x:1000:1000:Administrator:/home/admin:/bin/bash\n\
ftpuser:x:1001:1001:FTP User:/home/ftpuser:/bin/bash\n\
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n".to_vec()
            }))
        );
    }

    /// Add a directory to the filesystem
    fn add_directory(&mut self, path: &str, owner: &str, group: &str, permissions: &str) {
        let pathbuf = PathBuf::from(path);
        let name = pathbuf.file_name().unwrap_or_default().to_string_lossy().to_string();

        self.files.insert(pathbuf, VirtualFile {
            name: if name.is_empty() { "/".to_string() } else { name },
            is_directory: true,
            size: 4096,
            permissions: permissions.to_string(),
            owner: owner.to_string(),
            group: group.to_string(),
            modified: Utc::now().format("%b %d %H:%M").to_string(),
            content: FileContent::Empty,
        });
    }

    /// Add a file to the filesystem
    fn add_file(&mut self, path: &str, owner: &str, group: &str, permissions: &str, content: FileContent) {
        let pathbuf = PathBuf::from(path);
        let name = pathbuf.file_name().unwrap().to_string_lossy().to_string();

        let size = match &content {
            FileContent::Static(data) => data.len() as u64,
            FileContent::Large(s) => *s,
            _ => 0,
        };

        self.files.insert(pathbuf, VirtualFile {
            name,
            is_directory: false,
            size,
            permissions: permissions.to_string(),
            owner: owner.to_string(),
            group: group.to_string(),
            modified: Utc::now().format("%b %d %H:%M").to_string(),
            content,
        });
    }

    /// List directory contents
    pub fn list_directory(&self, path: &Path) -> Vec<&VirtualFile> {
        let path_str = path.to_string_lossy();
        let path_str = if path_str == "/" { "" } else { path_str.as_ref() };

        self.files
            .iter()
            .filter_map(|(p, f)| {
                let parent = p.parent().map(|pa| pa.to_string_lossy().to_string()).unwrap_or_else(|| "/".to_string());

                // Match files in this directory
                if (path_str.is_empty() && parent == "/") || parent == path_str {
                    Some(f)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get a file by path
    pub fn get_file(&self, path: &Path) -> Option<&VirtualFile> {
        self.files.get(path)
    }

    /// Check if path exists
    pub fn exists(&self, path: &Path) -> bool {
        self.files.contains_key(path)
    }

    /// Check if path is a directory
    pub fn is_directory(&self, path: &Path) -> bool {
        self.files.get(path).map(|f| f.is_directory).unwrap_or(false)
    }

    /// Generate file content
    pub fn get_file_content(&self, path: &Path) -> Option<Vec<u8>> {
        let file = self.files.get(path)?;

        match &file.content {
            FileContent::Static(data) => Some(data.to_vec()),
            FileContent::Generated(gen) => Some(gen()),
            FileContent::Empty => Some(Vec::new()),
            FileContent::Large(_size) => {
                // Generate fake content for large files
                Some(vec![0u8; 1024]) // Just return 1KB of zeros as placeholder
            }
        }
    }
}

impl Default for VirtualFilesystem {
    fn default() -> Self {
        Self::new()
    }
}
