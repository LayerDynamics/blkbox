// FTP Command Parsing
// Parses and handles FTP protocol commands (RFC 959)

use anyhow::{Result, anyhow};

/// FTP Commands
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FtpCommand {
    // Authentication
    User(String),
    Pass(String),
    Acct(String),
    Quit,

    // Navigation
    Pwd,
    Cwd(String),
    Cdup,

    // Listing
    List(Option<String>),
    Nlst(Option<String>),
    Stat(Option<String>),

    // File operations
    Retr(String),
    Stor(String),
    Dele(String),
    Rnfr(String),
    Rnto(String),
    Mkd(String),
    Rmd(String),

    // Data connection
    Pasv,
    Port(String),
    Type(String),
    Mode(String),
    Stru(String),

    // System
    Syst,
    Noop,
    Help(Option<String>),
    Feat,
    Opts(String, String),
    Size(String),
    Mdtm(String),
    Rest(u64),
    Abor,
    Allo(u64),

    // Client identification
    Clnt(String),
}

impl FtpCommand {
    /// Parse an FTP command from a string
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();

        if input.is_empty() {
            return Err(anyhow!("Empty command"));
        }

        // Split into command and arguments
        let mut parts = input.splitn(2, ' ');
        let cmd = parts.next().unwrap().to_uppercase();
        let args = parts.next().map(|s| s.trim().to_string());

        let command = match cmd.as_str() {
            // Authentication
            "USER" => {
                let username = args.ok_or_else(|| anyhow!("USER requires username"))?;
                FtpCommand::User(username)
            }
            "PASS" => {
                let password = args.ok_or_else(|| anyhow!("PASS requires password"))?;
                FtpCommand::Pass(password)
            }
            "ACCT" => {
                let account = args.ok_or_else(|| anyhow!("ACCT requires account"))?;
                FtpCommand::Acct(account)
            }
            "QUIT" => FtpCommand::Quit,

            // Navigation
            "PWD" | "XPWD" => FtpCommand::Pwd,
            "CWD" | "XCWD" => {
                let path = args.ok_or_else(|| anyhow!("CWD requires path"))?;
                FtpCommand::Cwd(path)
            }
            "CDUP" | "XCUP" => FtpCommand::Cdup,

            // Listing
            "LIST" => FtpCommand::List(args),
            "NLST" => FtpCommand::Nlst(args),
            "STAT" => FtpCommand::Stat(args),

            // File operations
            "RETR" => {
                let filename = args.ok_or_else(|| anyhow!("RETR requires filename"))?;
                FtpCommand::Retr(filename)
            }
            "STOR" => {
                let filename = args.ok_or_else(|| anyhow!("STOR requires filename"))?;
                FtpCommand::Stor(filename)
            }
            "DELE" => {
                let filename = args.ok_or_else(|| anyhow!("DELE requires filename"))?;
                FtpCommand::Dele(filename)
            }
            "RNFR" => {
                let from = args.ok_or_else(|| anyhow!("RNFR requires filename"))?;
                FtpCommand::Rnfr(from)
            }
            "RNTO" => {
                let to = args.ok_or_else(|| anyhow!("RNTO requires filename"))?;
                FtpCommand::Rnto(to)
            }
            "MKD" | "XMKD" => {
                let dirname = args.ok_or_else(|| anyhow!("MKD requires directory name"))?;
                FtpCommand::Mkd(dirname)
            }
            "RMD" | "XRMD" => {
                let dirname = args.ok_or_else(|| anyhow!("RMD requires directory name"))?;
                FtpCommand::Rmd(dirname)
            }

            // Data connection
            "PASV" => FtpCommand::Pasv,
            "PORT" => {
                let addr = args.ok_or_else(|| anyhow!("PORT requires address"))?;
                FtpCommand::Port(addr)
            }
            "TYPE" => {
                let type_code = args.ok_or_else(|| anyhow!("TYPE requires type code"))?;
                FtpCommand::Type(type_code)
            }
            "MODE" => {
                let mode = args.ok_or_else(|| anyhow!("MODE requires mode"))?;
                FtpCommand::Mode(mode)
            }
            "STRU" => {
                let structure = args.ok_or_else(|| anyhow!("STRU requires structure"))?;
                FtpCommand::Stru(structure)
            }

            // System
            "SYST" => FtpCommand::Syst,
            "NOOP" => FtpCommand::Noop,
            "HELP" => FtpCommand::Help(args),
            "FEAT" => FtpCommand::Feat,
            "OPTS" => {
                if let Some(opts) = args {
                    let mut opt_parts = opts.splitn(2, ' ');
                    let option = opt_parts.next().unwrap().to_string();
                    let value = opt_parts.next().unwrap_or("").to_string();
                    FtpCommand::Opts(option, value)
                } else {
                    return Err(anyhow!("OPTS requires option"));
                }
            }
            "SIZE" => {
                let filename = args.ok_or_else(|| anyhow!("SIZE requires filename"))?;
                FtpCommand::Size(filename)
            }
            "MDTM" => {
                let filename = args.ok_or_else(|| anyhow!("MDTM requires filename"))?;
                FtpCommand::Mdtm(filename)
            }
            "REST" => {
                let offset = args
                    .ok_or_else(|| anyhow!("REST requires offset"))?
                    .parse::<u64>()
                    .map_err(|_| anyhow!("REST offset must be number"))?;
                FtpCommand::Rest(offset)
            }
            "ABOR" => FtpCommand::Abor,
            "ALLO" => {
                let size = args
                    .ok_or_else(|| anyhow!("ALLO requires size"))?
                    .split(' ')
                    .next()
                    .unwrap()
                    .parse::<u64>()
                    .map_err(|_| anyhow!("ALLO size must be number"))?;
                FtpCommand::Allo(size)
            }

            // Client identification
            "CLNT" => {
                let client = args.ok_or_else(|| anyhow!("CLNT requires client name"))?;
                FtpCommand::Clnt(client)
            }

            _ => {
                return Err(anyhow!("Unknown command: {}", cmd));
            }
        };

        Ok(command)
    }

    /// Get the command name as a string
    pub fn name(&self) -> &'static str {
        match self {
            FtpCommand::User(_) => "USER",
            FtpCommand::Pass(_) => "PASS",
            FtpCommand::Acct(_) => "ACCT",
            FtpCommand::Quit => "QUIT",
            FtpCommand::Pwd => "PWD",
            FtpCommand::Cwd(_) => "CWD",
            FtpCommand::Cdup => "CDUP",
            FtpCommand::List(_) => "LIST",
            FtpCommand::Nlst(_) => "NLST",
            FtpCommand::Stat(_) => "STAT",
            FtpCommand::Retr(_) => "RETR",
            FtpCommand::Stor(_) => "STOR",
            FtpCommand::Dele(_) => "DELE",
            FtpCommand::Rnfr(_) => "RNFR",
            FtpCommand::Rnto(_) => "RNTO",
            FtpCommand::Mkd(_) => "MKD",
            FtpCommand::Rmd(_) => "RMD",
            FtpCommand::Pasv => "PASV",
            FtpCommand::Port(_) => "PORT",
            FtpCommand::Type(_) => "TYPE",
            FtpCommand::Mode(_) => "MODE",
            FtpCommand::Stru(_) => "STRU",
            FtpCommand::Syst => "SYST",
            FtpCommand::Noop => "NOOP",
            FtpCommand::Help(_) => "HELP",
            FtpCommand::Feat => "FEAT",
            FtpCommand::Opts(_, _) => "OPTS",
            FtpCommand::Size(_) => "SIZE",
            FtpCommand::Mdtm(_) => "MDTM",
            FtpCommand::Rest(_) => "REST",
            FtpCommand::Abor => "ABOR",
            FtpCommand::Allo(_) => "ALLO",
            FtpCommand::Clnt(_) => "CLNT",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_user() {
        let cmd = FtpCommand::parse("USER admin").unwrap();
        assert_eq!(cmd, FtpCommand::User("admin".to_string()));
    }

    #[test]
    fn test_parse_pass() {
        let cmd = FtpCommand::parse("PASS secret123").unwrap();
        assert_eq!(cmd, FtpCommand::Pass("secret123".to_string()));
    }

    #[test]
    fn test_parse_quit() {
        let cmd = FtpCommand::parse("QUIT").unwrap();
        assert_eq!(cmd, FtpCommand::Quit);
    }

    #[test]
    fn test_parse_cwd() {
        let cmd = FtpCommand::parse("CWD /pub").unwrap();
        assert_eq!(cmd, FtpCommand::Cwd("/pub".to_string()));
    }

    #[test]
    fn test_parse_type() {
        let cmd = FtpCommand::parse("TYPE I").unwrap();
        assert_eq!(cmd, FtpCommand::Type("I".to_string()));
    }

    #[test]
    fn test_parse_pasv() {
        let cmd = FtpCommand::parse("PASV").unwrap();
        assert_eq!(cmd, FtpCommand::Pasv);
    }

    #[test]
    fn test_parse_list() {
        let cmd = FtpCommand::parse("LIST").unwrap();
        assert_eq!(cmd, FtpCommand::List(None));

        let cmd = FtpCommand::parse("LIST /pub").unwrap();
        assert_eq!(cmd, FtpCommand::List(Some("/pub".to_string())));
    }

    #[test]
    fn test_parse_unknown() {
        let result = FtpCommand::parse("INVALID");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_case_insensitive() {
        let cmd = FtpCommand::parse("user admin").unwrap();
        assert_eq!(cmd, FtpCommand::User("admin".to_string()));
    }

    #[test]
    fn test_command_name() {
        let cmd = FtpCommand::parse("USER admin").unwrap();
        assert_eq!(cmd.name(), "USER");

        let cmd = FtpCommand::parse("PASS secret").unwrap();
        assert_eq!(cmd.name(), "PASS");

        let cmd = FtpCommand::parse("QUIT").unwrap();
        assert_eq!(cmd.name(), "QUIT");

        let cmd = FtpCommand::parse("CWD /pub").unwrap();
        assert_eq!(cmd.name(), "CWD");

        let cmd = FtpCommand::parse("LIST").unwrap();
        assert_eq!(cmd.name(), "LIST");

        let cmd = FtpCommand::parse("PASV").unwrap();
        assert_eq!(cmd.name(), "PASV");

        let cmd = FtpCommand::parse("OPTS UTF8 ON").unwrap();
        assert_eq!(cmd.name(), "OPTS");
    }
}
