// HTTP/HTTPS Honeypot Implementation
// Serves realistic fake web applications to attract and log attackers

use super::traits::{HoneypotService, HoneypotStats, RequestContext, fingerprint};
use crate::ffi::types::{AttackEvent, ServiceType};
use crate::tracking::{extract_real_ip, extract_cloudflare_metadata};
use crate::tracking::fingerprint::{fingerprint_tool_detection, detect_attack_tool};
use anyhow::{Result, Context as _};
use async_trait::async_trait;
use axum::{
    Router,
    routing::{get, any},
    extract::{State, Path, Request},
    response::{Html, IntoResponse},
    http::{StatusCode, HeaderMap},
};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use std::net::SocketAddr;
use std::time::Instant;

/// HTTP Honeypot Service
/// Emulates various web applications to attract attackers
pub struct HttpHoneypot {
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
}

impl HttpHoneypot {
    /// Create a new HTTP honeypot
    pub fn new(port: u16, service_id: u32) -> Self {
        Self {
            port,
            service_id,
            running: Arc::new(Mutex::new(false)),
            stats: Arc::new(Mutex::new(HoneypotStats::default())),
            start_time: None,
            event_sender: None,
            shutdown_tx: None,
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

    /// Build the Axum router with all honeypot routes
    fn build_router(state: Arc<HttpHoneypotState>) -> Router {
        Router::new()
            // Root
            .route("/", get(handle_root))

            // WordPress honeypot routes
            .route("/wp-admin", any(handle_wp_admin))
            .route("/wp-admin/", any(handle_wp_admin))
            .route("/wp-login.php", any(handle_wp_login))
            .route("/wp-admin/admin-ajax.php", any(handle_wp_ajax))
            .route("/wp-content/*path", any(handle_wp_content))
            .route("/wp-includes/*path", any(handle_wp_includes))
            .route("/xmlrpc.php", any(handle_xmlrpc))

            // Git exposure honeypot
            .route("/.git/config", any(handle_git_config))
            .route("/.git/HEAD", any(handle_git_head))
            .route("/.git/*path", any(handle_git_path))

            // Common attack targets
            .route("/.env", any(handle_env_file))
            .route("/config.php", any(handle_config))
            .route("/phpinfo.php", any(handle_phpinfo))
            .route("/admin", any(handle_admin))
            .route("/admin/", any(handle_admin))
            .route("/phpmyadmin", any(handle_phpmyadmin))
            .route("/phpmyadmin/", any(handle_phpmyadmin))
            .route("/backup.sql", any(handle_backup))
            .route("/database.sql", any(handle_backup))

            // Catch-all for any other requests
            .fallback(handle_404)

            .with_state(state)
    }
}

#[async_trait]
impl HoneypotService for HttpHoneypot {
    fn service_type(&self) -> ServiceType {
        ServiceType::HTTP
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
        let state = Arc::new(HttpHoneypotState {
            service_id: self.service_id,
            stats: Arc::clone(&self.stats),
            event_sender: self.event_sender.clone(),
        });

        // Build the router
        let app = Self::build_router(state);

        // Bind to address
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .context(format!("Failed to bind HTTP honeypot to port {}", self.port))?;

        println!("HTTP honeypot listening on {}", addr);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn server in background
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    shutdown_rx.await.ok();
                })
                .await
                .expect("HTTP server failed");
        });

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

        *running = false;
        println!("HTTP honeypot on port {} stopped", self.port);

        Ok(())
    }

    fn is_running(&self) -> bool {
        // This is a synchronous method, so we can't await
        // For now, return a simple check
        false // TODO: Fix this properly
    }

    fn stats(&self) -> HoneypotStats {
        // This is synchronous, so we can't await
        // Return a default for now
        HoneypotStats::default() // TODO: Fix this properly
    }
}

/// Shared state passed to all request handlers
#[derive(Clone)]
struct HttpHoneypotState {
    service_id: u32,
    stats: Arc<Mutex<HoneypotStats>>,
    event_sender: Option<mpsc::UnboundedSender<AttackEvent>>,
}

impl HttpHoneypotState {
    /// Log an attack event from a request
    async fn log_attack(&self, ctx: RequestContext) {
        // Update stats
        let mut stats = self.stats.lock().await;
        stats.total_connections += 1;
        stats.total_attacks += 1;

        // Send event to runtime if sender is available
        if let Some(sender) = &self.event_sender {
            let event = ctx.to_attack_event();
            let _ = sender.send(event);
        }
    }

    /// Extract request context from Axum request
    fn extract_context(
        &self,
        req: &Request,
        socket_addr: SocketAddr,
    ) -> RequestContext {
        let headers = req.headers();
        let method = req.method().as_str();
        let uri = req.uri();
        let path = uri.path();

        // Extract real IP from headers (CF-Connecting-IP, X-Forwarded-For, etc.)
        let real_ip = extract_real_ip(headers, &socket_addr.to_string());

        // Parse real IP to SocketAddr (keep original port)
        let client_addr = real_ip
            .parse::<std::net::IpAddr>()
            .map(|ip| SocketAddr::new(ip, socket_addr.port()))
            .unwrap_or(socket_addr);

        // Extract User-Agent
        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Build payload string
        let payload = format!(
            "{} {} {:?}\n{}",
            method,
            uri,
            req.version(),
            headers_to_string(headers)
        );

        // Calculate threat level
        let threat_level = fingerprint::calculate_threat_level(
            &user_agent,
            path,
            method,
        );

        // Detect attack tool from User-Agent and path patterns
        let tool_detected = detect_attack_tool(
            user_agent.as_deref().unwrap_or(""),
            path
        );

        // Generate tool detection fingerprint if a tool was detected
        let tool_fingerprint = fingerprint_tool_detection(
            user_agent.as_deref().unwrap_or(""),
            path
        );

        // Use tool fingerprint value as the fingerprint string
        let fingerprint_value = tool_fingerprint.map(|fp| fp.value);

        // Extract Cloudflare metadata if present
        let cf_metadata = extract_cloudflare_metadata(headers).map(|cf| {
            let mut map = std::collections::HashMap::new();
            if let Some(ray) = cf.cf_ray {
                map.insert("cf_ray".to_string(), ray);
            }
            if let Some(ip) = cf.cf_connecting_ip {
                map.insert("cf_connecting_ip".to_string(), ip);
            }
            if let Some(country) = cf.cf_ipcountry {
                map.insert("cf_ipcountry".to_string(), country);
            }
            if let Some(visitor) = cf.cf_visitor {
                map.insert("cf_visitor".to_string(), visitor);
            }
            if let Some(score) = cf.cf_threat_score {
                map.insert("cf_threat_score".to_string(), score.to_string());
            }
            if let Some(request_id) = cf.cf_request_id {
                map.insert("cf_request_id".to_string(), request_id);
            }
            if let Some(colo) = cf.cf_colo {
                map.insert("cf_colo".to_string(), colo);
            }
            if let Some(tool) = tool_detected {
                map.insert("detected_tool".to_string(), tool);
            }
            map
        });

        RequestContext {
            client_addr,
            service_id: self.service_id,
            service_type: ServiceType::HTTP,
            user_agent,
            payload,
            threat_level,
            fingerprint: fingerprint_value,
            cf_metadata,
        }
    }
}

/// Convert HeaderMap to readable string
fn headers_to_string(headers: &HeaderMap) -> String {
    headers
        .iter()
        .map(|(name, value)| {
            format!("{}: {}", name, value.to_str().unwrap_or("<binary>"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ========================================
// Route Handlers
// ========================================

/// Root page - generic website
async fn handle_root(State(state): State<Arc<HttpHoneypotState>>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0)); // TODO: Extract real IP
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <h1>Welcome to Our Site</h1>
    <p>This is a generic website.</p>
</body>
</html>
    "#)
}

/// WordPress admin panel
async fn handle_wp_admin(State(state): State<Arc<HttpHoneypotState>>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    Html(r#"
<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Dashboard &lsaquo; My Blog &mdash; WordPress</title>
    <link rel='stylesheet' id='buttons-css' href='/wp-includes/css/buttons.min.css' type='text/css' media='all' />
</head>
<body class="wp-admin wp-core-ui">
    <div id="wpwrap">
        <div id="wpcontent">
            <div id="wpbody">
                <h1>Dashboard</h1>
                <p>WordPress 6.4.2</p>
                <div class="wrap">
                    <h2>Welcome to WordPress!</h2>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
    "#)
}

/// WordPress login page
async fn handle_wp_login(State(state): State<Arc<HttpHoneypotState>>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    Html(r#"
<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Log In &lsaquo; My Blog &mdash; WordPress</title>
</head>
<body class="login login-action-login wp-core-ui">
    <div id="login">
        <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
        <form name="loginform" id="loginform" action="/wp-login.php" method="post">
            <p>
                <label for="user_login">Username or Email Address</label>
                <input type="text" name="log" id="user_login" class="input" value="" size="20" />
            </p>
            <p>
                <label for="user_pass">Password</label>
                <input type="password" name="pwd" id="user_pass" class="input" value="" size="20" />
            </p>
            <p class="submit">
                <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
            </p>
        </form>
    </div>
</body>
</html>
    "#)
}

/// WordPress AJAX endpoint
async fn handle_wp_ajax(State(state): State<Arc<HttpHoneypotState>>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    (StatusCode::BAD_REQUEST, "0")
}

/// WordPress content directory
async fn handle_wp_content(State(state): State<Arc<HttpHoneypotState>>, Path(_path): Path<String>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    StatusCode::NOT_FOUND
}

/// WordPress includes directory
async fn handle_wp_includes(State(state): State<Arc<HttpHoneypotState>>, Path(_path): Path<String>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    StatusCode::NOT_FOUND
}

/// XML-RPC endpoint (commonly attacked)
async fn handle_xmlrpc(State(state): State<Arc<HttpHoneypotState>>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    (
        StatusCode::OK,
        [("Content-Type", "text/xml")],
        r#"<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>-32601</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>server error. requested method not found</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>"#
    )
}

/// Git config file exposure
async fn handle_git_config(State(state): State<Arc<HttpHoneypotState>>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    (
        StatusCode::OK,
        [("Content-Type", "text/plain")],
        r#"[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/example/myapp.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
	remote = origin
	merge = refs/heads/master
"#
    )
}

/// Git HEAD file
async fn handle_git_head(State(state): State<Arc<HttpHoneypotState>>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    (StatusCode::OK, "ref: refs/heads/master\n")
}

/// Git directory paths
async fn handle_git_path(State(state): State<Arc<HttpHoneypotState>>, Path(_path): Path<String>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    StatusCode::NOT_FOUND
}

/// .env file exposure
async fn handle_env_file(State(state): State<Arc<HttpHoneypotState>>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    (
        StatusCode::OK,
        [("Content-Type", "text/plain")],
        r#"APP_NAME=MyApp
APP_ENV=production
APP_DEBUG=false
APP_URL=http://example.com

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=myapp_db
DB_USERNAME=myapp_user
DB_PASSWORD=SuperSecretPassword123!

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
"#
    )
}

/// Config.php file
async fn handle_config(State(state): State<Arc<HttpHoneypotState>>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    StatusCode::FORBIDDEN
}

/// PHPInfo page
async fn handle_phpinfo(State(state): State<Arc<HttpHoneypotState>>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    Html(r#"
<!DOCTYPE html>
<html><head><title>phpinfo()</title></head>
<body>
<h1>PHP Version 8.1.12</h1>
<table>
<tr><td>System</td><td>Linux server 5.15.0 x86_64</td></tr>
<tr><td>Build Date</td><td>Nov 22 2023</td></tr>
<tr><td>Server API</td><td>FPM/FastCGI</td></tr>
</table>
</body>
</html>
    "#)
}

/// Generic admin panel
async fn handle_admin(State(state): State<Arc<HttpHoneypotState>>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    Html(r#"
<!DOCTYPE html>
<html>
<head><title>Admin Login</title></head>
<body>
    <h1>Admin Panel</h1>
    <form method="post">
        <input type="text" name="username" placeholder="Username" />
        <input type="password" name="password" placeholder="Password" />
        <button type="submit">Login</button>
    </form>
</body>
</html>
    "#)
}

/// phpMyAdmin
async fn handle_phpmyadmin(State(state): State<Arc<HttpHoneypotState>>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    Html(r#"
<!DOCTYPE html>
<html>
<head><title>phpMyAdmin</title></head>
<body>
    <h1>phpMyAdmin 5.2.0</h1>
    <form method="post">
        <input type="text" name="pma_username" placeholder="Username" />
        <input type="password" name="pma_password" placeholder="Password" />
        <button type="submit">Go</button>
    </form>
</body>
</html>
    "#)
}

/// Backup SQL files
async fn handle_backup(State(state): State<Arc<HttpHoneypotState>>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    StatusCode::FORBIDDEN
}

/// 404 catch-all
async fn handle_404(State(state): State<Arc<HttpHoneypotState>>, req: Request) -> impl IntoResponse {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ctx = state.extract_context(&req, client_addr);
    state.log_attack(ctx).await;

    (
        StatusCode::NOT_FOUND,
        Html(r#"
<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
    <h1>404 Not Found</h1>
    <p>The requested resource was not found on this server.</p>
</body>
</html>
        "#)
    )
}
