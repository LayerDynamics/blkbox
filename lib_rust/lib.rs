// BlkBox Honeypot System - Rust FFI Library
// Main entry point for FFI exports to Deno

mod ffi;
mod storage;
mod honeypot;
mod tracking;
mod strikeback;

use std::os::raw::c_char;
use std::collections::HashMap;
use crate::tracking::{Fingerprint, SessionIdentifier};
use std::ptr;
use ffi::types::{BlkBoxRuntime, ServiceType, PayloadType, AttackEvent};
use ffi::types::ffi_helpers;

/// Initialize BlkBox runtime
/// Returns a pointer to the runtime or null on error
///
/// # Safety
/// The returned pointer must be freed with blkbox_free()
#[no_mangle]
pub extern "C" fn blkbox_init() -> *mut BlkBoxRuntime {
    match BlkBoxRuntime::new() {
        Ok(runtime) => Box::into_raw(Box::new(runtime)),
        Err(e) => {
            eprintln!("Failed to initialize BlkBox runtime: {}", e);
            ptr::null_mut()
        }
    }
}

/// Start a honeypot service
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
/// * `service_type` - Type of service (0=HTTP, 1=HTTPS, 2=SSH, etc.)
/// * `port` - Port number to listen on
/// * `config_json` - JSON configuration string
///
/// # Returns
/// Service ID on success, -1 on error
///
/// # Safety
/// runtime pointer must be valid
/// config_json must be a valid null-terminated string
#[no_mangle]
pub extern "C" fn blkbox_start_honeypot(
    runtime: *mut BlkBoxRuntime,
    service_type: u8,
    port: u16,
    config_json: *const c_char,
) -> i32 {
    if runtime.is_null() {
        eprintln!("blkbox_start_honeypot: null runtime pointer");
        return -1;
    }

    let runtime = unsafe { &mut *runtime };

    // Parse service type
    let service_type = match ServiceType::from_u8(service_type) {
        Some(st) => st,
        None => {
            eprintln!("blkbox_start_honeypot: invalid service type: {}", service_type);
            return -1;
        }
    };

    // Parse config JSON
    let config_str = unsafe {
        match ffi_helpers::c_str_to_string(config_json) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("blkbox_start_honeypot: failed to parse config: {}", e);
                return -1;
            }
        }
    };

    // Parse ServiceConfig from JSON
    let service_config = match ffi_helpers::parse_service_config(&config_str) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("blkbox_start_honeypot: invalid service config: {}", e);
            return -1;
        }
    };

    // Check if service is enabled in config
    if !service_config.enabled {
        eprintln!("blkbox_start_honeypot: service is disabled in config");
        return -1;
    }

    // Get next service ID
    let service_id = runtime.get_next_service_id();

    // Start the appropriate honeypot based on service type
    let (result, shutdown_tx) = match service_type {
        ServiceType::HTTP | ServiceType::HTTPS => {
            // Create HTTP honeypot
            use honeypot::http::HttpHoneypot;
            use honeypot::traits::HoneypotService;

            let mut honeypot = HttpHoneypot::new(port, service_id)
                .with_event_sender(runtime.event_sender.clone());

            // Start the honeypot on the tokio runtime
            let start_result = runtime.tokio_runtime.block_on(async {
                honeypot.start().await
            });

            // Extract shutdown_tx
            let shutdown = honeypot.take_shutdown_tx();

            (start_result, shutdown)
        }
        ServiceType::SSH => {
            // Create SSH honeypot
            use honeypot::ssh::SshHoneypot;
            use honeypot::traits::HoneypotService;

            let mut honeypot = SshHoneypot::new(port, service_id)
                .with_event_sender(runtime.event_sender.clone());

            // Start the honeypot on the tokio runtime
            let start_result = runtime.tokio_runtime.block_on(async {
                honeypot.start().await
            });

            // Extract shutdown_tx
            let shutdown = honeypot.take_shutdown_tx();

            (start_result, shutdown)
        }
        ServiceType::FTP => {
            // Create FTP honeypot
            use honeypot::ftp::FtpHoneypot;
            use honeypot::traits::HoneypotService;

            let mut honeypot = FtpHoneypot::new(port, service_id)
                .with_event_sender(runtime.event_sender.clone());

            // Start the honeypot on the tokio runtime
            let start_result = runtime.tokio_runtime.block_on(async {
                honeypot.start().await
            });

            // Extract shutdown_tx
            let shutdown = honeypot.take_shutdown_tx();

            (start_result, shutdown)
        }
        _ => {
            eprintln!("Service type {} not yet implemented", service_type.as_str());
            return -1;
        }
    };

    // Check if start was successful
    if let Err(e) = result {
        eprintln!("Failed to start {} honeypot: {}", service_type.as_str(), e);
        return -1;
    }

    // Create service handle with shutdown signal
    let handle = ffi::types::ServiceHandle {
        service_id,
        service_type,
        port,
        active: true,
        shutdown_tx,
    };

    runtime.services.lock().unwrap().insert(service_id, handle);

    println!(
        "Started {} honeypot on port {} with ID {}",
        service_type.as_str(),
        port,
        service_id
    );

    service_id as i32
}

/// Stop a honeypot service
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
/// * `service_id` - ID of service to stop
///
/// # Returns
/// 0 on success, -1 on error
///
/// # Safety
/// runtime pointer must be valid
#[no_mangle]
pub extern "C" fn blkbox_stop_honeypot(
    runtime: *mut BlkBoxRuntime,
    service_id: u32,
) -> i32 {
    if runtime.is_null() {
        eprintln!("blkbox_stop_honeypot: null runtime pointer");
        return -1;
    }

    let runtime = unsafe { &mut *runtime };

    let mut services = runtime.services.lock().unwrap();

    if let Some(mut handle) = services.remove(&service_id) {
        // Send shutdown signal if available
        if let Some(shutdown_tx) = handle.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        handle.active = false;
        println!("Stopped service {}", service_id);
        0
    } else {
        eprintln!("blkbox_stop_honeypot: service {} not found", service_id);
        -1
    }
}

/// Get attack events from the queue
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
/// * `buffer` - Buffer to write JSON array of events
/// * `buffer_len` - Length of buffer
///
/// # Returns
/// Number of bytes written on success, -1 on error
///
/// # Safety
/// runtime and buffer pointers must be valid
/// buffer must have at least buffer_len bytes available
#[no_mangle]
pub extern "C" fn blkbox_get_events(
    runtime: *mut BlkBoxRuntime,
    buffer: *mut c_char,
    buffer_len: usize,
) -> i32 {
    if runtime.is_null() || buffer.is_null() {
        eprintln!("blkbox_get_events: null pointer");
        return -1;
    }

    let runtime = unsafe { &mut *runtime };

    // Drain events from queue
    let events = runtime.drain_events();

    // Convert to JSON
    let json = ffi_helpers::events_to_json(events);

    // Copy to buffer
    let bytes = json.as_bytes();
    if bytes.len() + 1 > buffer_len {
        eprintln!(
            "blkbox_get_events: buffer too small (need {}, have {})",
            bytes.len() + 1,
            buffer_len
        );
        return -1;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, bytes.len());
        *buffer.add(bytes.len()) = 0; // Null terminator
    }

    bytes.len() as i32
}

/// Trigger strikeback payload deployment
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
/// * `attacker_ip` - IP address of attacker
/// * `payload_type` - Type of payload to deploy
///
/// # Returns
/// 0 on success, -1 on error
///
/// # Safety
/// runtime pointer must be valid
/// attacker_ip must be a valid null-terminated string
#[no_mangle]
pub extern "C" fn blkbox_trigger_strikeback(
    runtime: *mut BlkBoxRuntime,
    attacker_ip: *const c_char,
    payload_type: u8,
) -> i32 {
    if runtime.is_null() {
        eprintln!("blkbox_trigger_strikeback: null runtime pointer");
        return -1;
    }

    let runtime = unsafe { &mut *runtime };

    let ip_str = unsafe {
        match ffi_helpers::c_str_to_string(attacker_ip) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("blkbox_trigger_strikeback: failed to parse IP: {}", e);
                return -1;
            }
        }
    };

    let payload_type = match PayloadType::from_u8(payload_type) {
        Some(pt) => pt,
        None => {
            eprintln!("blkbox_trigger_strikeback: invalid payload type: {}", payload_type);
            return -1;
        }
    };

    // Create a synthetic attack event for manual strikeback trigger
    let event = AttackEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        source_ip: ip_str.clone(),
        source_port: 0,
        service_type: ServiceType::HTTP, // Default to HTTP for manual triggers
        service_id: 0,
        user_agent: Some("Manual Strikeback Trigger".to_string()),
        payload: format!("Manual strikeback deployment: {:?}", payload_type),
        threat_level: 10, // Maximum threat for manual triggers
        fingerprint: None,
        cf_metadata: None,
        attack_id: None,
    };

    // Choose appropriate delivery method based on payload type
    use crate::strikeback::delivery::DeliveryMethod;
    let delivery_method = match payload_type {
        PayloadType::SystemInfo | PayloadType::Beacon => DeliveryMethod::HttpInject,
        PayloadType::BrowserRecon => DeliveryMethod::HttpInject,
        PayloadType::NetworkScanner => DeliveryMethod::SshOutput,
        PayloadType::ReverseTCP => DeliveryMethod::HttpRedirect,
        PayloadType::CommandInjection => DeliveryMethod::SshOutput,
        PayloadType::FileExfiltration => DeliveryMethod::FtpFile,
        _ => DeliveryMethod::HttpInject,
    };

    // Deploy payload using strikeback service
    let strikeback_clone = runtime.strikeback_service.clone();
    let result = runtime.tokio_runtime.block_on(async move {
        strikeback_clone.deploy_payload(&event, payload_type, delivery_method).await
    });

    match result {
        Ok(payload) => {
            println!(
                "Successfully deployed {:?} payload to {} (ID: {})",
                payload_type, ip_str, payload.payload_id
            );
            0
        }
        Err(e) => {
            eprintln!("Failed to deploy payload: {}", e);
            -1
        }
    }
}

/// Create SessionData from an AttackEvent by parsing the payload
/// Extracts session information for interactive services like FTP and SSH
fn create_session_data_from_event(event: &AttackEvent, attack_id: i64) -> crate::storage::models::SessionData {
    use crate::storage::models::SessionData;

    let mut commands = Vec::new();
    let queries = Vec::new();
    let files_accessed = Vec::new();

    // Parse payload based on service type
    match event.service_type {
        ServiceType::FTP => {
            // FTP payload format: "FTP session [ID: xxx]: N commands [cmd1, cmd2, ...], X bytes uploaded, Y bytes downloaded, Z files accessed"
            // Extract commands from within square brackets
            if let Some(start) = event.payload.find('[') {
                if let Some(end) = event.payload[start..].find(']') {
                    let commands_str = &event.payload[start + 1..start + end];
                    // Split by comma and trim
                    commands = commands_str
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty() && s != "...")
                        .collect();
                }
            }

            // Extract files count - files_accessed list isn't in payload, but we know there are some
            // We'll leave files_accessed empty for now as detailed list isn't in payload
        }
        ServiceType::SSH => {
            // SSH attacks typically have commands in the payload
            // Parse any command-like patterns from the payload
            if event.payload.contains("command") || event.payload.contains("exec") {
                commands.push(event.payload.clone());
            }
        }
        _ => {
            // For other service types, just store the payload as a command
            commands.push(event.payload.clone());
        }
    }

    // Generate session token - use attack_id as the session identifier
    let session_token = format!("{}-{}-{}",
        event.service_type.as_str(),
        event.source_ip,
        attack_id
    );

    SessionData {
        session_token,
        attack_id,
        started_at: event.timestamp.clone(),
        ended_at: Some(event.timestamp.clone()), // Session ended at same time for single-event sessions
        commands,
        queries,
        files_accessed,
        metadata: None,
    }
}

/// Store an attack event in the database with geolocation enrichment
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
/// * `event_json` - JSON representation of attack event
///
/// # Returns
/// Row ID on success, -1 on error
///
/// # Safety
/// runtime pointer must be valid
/// event_json must be a valid null-terminated string
#[no_mangle]
pub extern "C" fn blkbox_store_event(
    runtime: *mut BlkBoxRuntime,
    event_json: *const c_char,
) -> i32 {
    if runtime.is_null() {
        eprintln!("blkbox_store_event: null runtime pointer");
        return -1;
    }

    let runtime = unsafe { &mut *runtime };

    let json_str = unsafe {
        match ffi_helpers::c_str_to_string(event_json) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("blkbox_store_event: failed to parse JSON: {}", e);
                return -1;
            }
        }
    };

    // Parse JSON to AttackEvent
    let event: AttackEvent = match serde_json::from_str(&json_str) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("blkbox_store_event: failed to deserialize event: {}", e);
            return -1;
        }
    };

    // Store base event in database
    let db = runtime.db.lock().unwrap();
    let attack_id = match db.store_event(&event) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("blkbox_store_event: database error: {}", e);
            return -1;
        }
    };
    drop(db); // Release lock before doing other operations

    // Generate fingerprints for the attack
    let mut fingerprint_map = std::collections::HashMap::new();
    if let Some(fp) = &event.fingerprint {
        fingerprint_map.insert("basic".to_string(), fp.clone());
    }

    // Use FingerprintEngine to generate additional fingerprints
    let connection_type = match event.service_type {
        ServiceType::SSH => "ssh",
        ServiceType::HTTPS => "tls",
        ServiceType::HTTP => "http",
        _ => "unknown",
    };

    let mut connection_data = std::collections::HashMap::new();
    if let Some(ua) = &event.user_agent {
        connection_data.insert("user_agent".to_string(), ua.clone());
    }

    let fingerprints = runtime.fingerprint_engine.fingerprint_connection(
        connection_type,
        &connection_data,
    );

    // Store fingerprints in database
    if !fingerprints.is_empty() {
        let db = runtime.db.lock().unwrap();
        if let Err(e) = db.insert_fingerprints(attack_id, &fingerprints) {
            eprintln!("Failed to store fingerprints for event {}: {}", attack_id, e);
        }
        drop(db);

        // Add to fingerprint map for session correlation
        for fp in &fingerprints {
            fingerprint_map.insert(
                fp.fingerprint_type.as_str().to_string(),
                fp.value.clone(),
            );
        }
    }

    // Correlate with existing sessions using SessionCorrelator
    if let Err(e) = runtime.session_correlator.correlate_attack(&event, attack_id, &fingerprint_map) {
        eprintln!("Failed to correlate session for event {}: {}", attack_id, e);
    }

    // Perform geolocation lookup and store
    // Convert cf_metadata HashMap to CloudflareMetadata for lookup
    let cf_meta = event.cf_metadata.as_ref()
        .and_then(|map| crate::storage::models::CloudflareMetadata::from_hashmap(map));

    if let Some(geo_data) = tracking::lookup_geolocation(
        &event.source_ip,
        cf_meta.as_ref(),
        &runtime.geoip_reader,
        Some(&runtime.geo_cache),
    ) {
        let db = runtime.db.lock().unwrap();
        if let Err(e) = db.insert_geolocation(attack_id, &geo_data) {
            eprintln!("Failed to store geolocation for event {}: {}", attack_id, e);
        }
    }

    // Create and store SessionData for interactive services (FTP, SSH)
    if matches!(event.service_type, ServiceType::FTP | ServiceType::SSH) {
        let session_data = create_session_data_from_event(&event, attack_id);

        let db = runtime.db.lock().unwrap();
        if let Err(e) = db.with_connection(|conn| {
            crate::storage::operations::upsert_session(conn, &session_data)
        }) {
            eprintln!("Failed to store session data for event {}: {}", attack_id, e);
        }
    }

    attack_id as i32
}

/// Update Cloudflare configuration
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
/// * `config_json` - JSON configuration
///
/// # Returns
/// 0 on success, -1 on error
///
/// # Safety
/// runtime pointer must be valid
/// config_json must be a valid null-terminated string
#[no_mangle]
pub extern "C" fn blkbox_cloudflare_update(
    runtime: *mut BlkBoxRuntime,
    config_json: *const c_char,
) -> i32 {
    if runtime.is_null() {
        eprintln!("blkbox_cloudflare_update: null runtime pointer");
        return -1;
    }

    let _runtime = unsafe { &mut *runtime };

    let config_str = unsafe {
        match ffi_helpers::c_str_to_string(config_json) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("blkbox_cloudflare_update: failed to parse config: {}", e);
                return -1;
            }
        }
    };

    // Parse CloudflareConfig from JSON
    let cf_config = match ffi::types::CloudflareConfig::from_json(&config_str) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("blkbox_cloudflare_update: invalid config: {}", e);
            return -1;
        }
    };

    // Validate required fields
    if cf_config.api_token.is_empty() || cf_config.zone_id.is_empty() {
        eprintln!("blkbox_cloudflare_update: api_token and zone_id are required");
        return -1;
    }

    // TODO: Implement actual Cloudflare API integration using cf_config
    println!(
        "Cloudflare configuration updated for zone: {} (API integration pending)",
        cf_config.zone_id
    );

    0
}

/// Geolocate an IP address
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
/// * `ip_address` - IP address to geolocate
/// * `buffer` - Buffer to write JSON result
/// * `buffer_len` - Length of buffer
///
/// # Returns
/// Number of bytes written on success, -1 on error
///
/// # Safety
/// runtime and buffer pointers must be valid
#[no_mangle]
pub extern "C" fn blkbox_geolocate_ip(
    runtime: *mut BlkBoxRuntime,
    ip_address: *const c_char,
    buffer: *mut c_char,
    buffer_len: usize,
) -> i32 {
    if runtime.is_null() || ip_address.is_null() || buffer.is_null() {
        eprintln!("blkbox_geolocate_ip: null pointer");
        return -1;
    }

    let runtime = unsafe { &*runtime };

    let ip_str = unsafe {
        match ffi_helpers::c_str_to_string(ip_address) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("blkbox_geolocate_ip: failed to parse IP: {}", e);
                return -1;
            }
        }
    };

    // Perform geolocation lookup
    let geo_data = match tracking::lookup_geolocation(
        &ip_str,
        None,
        &runtime.geoip_reader,
        Some(&runtime.geo_cache),
    ) {
        Some(data) => data,
        None => {
            eprintln!("blkbox_geolocate_ip: no geolocation data for IP: {}", ip_str);
            return -1;
        }
    };

    // Convert to JSON
    let json = match serde_json::to_string(&geo_data) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("blkbox_geolocate_ip: JSON serialization error: {}", e);
            return -1;
        }
    };

    // Copy to buffer
    let bytes = json.as_bytes();
    if bytes.len() + 1 > buffer_len {
        eprintln!(
            "blkbox_geolocate_ip: buffer too small (need {}, have {})",
            bytes.len() + 1,
            buffer_len
        );
        return -1;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, bytes.len());
        *buffer.add(bytes.len()) = 0; // Null terminator
    }

    bytes.len() as i32
}

/// Get session information for an IP address
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
/// * `ip_address` - IP address to query
/// * `buffer` - Buffer to write JSON array of sessions
/// * `buffer_len` - Length of buffer
///
/// # Returns
/// Number of bytes written on success, -1 on error
///
/// # Safety
/// runtime and buffer pointers must be valid
#[no_mangle]
pub extern "C" fn blkbox_get_ip_sessions(
    runtime: *mut BlkBoxRuntime,
    ip_address: *const c_char,
    buffer: *mut c_char,
    buffer_len: usize,
) -> i32 {
    if runtime.is_null() || ip_address.is_null() || buffer.is_null() {
        eprintln!("blkbox_get_ip_sessions: null pointer");
        return -1;
    }

    let runtime = unsafe { &*runtime };

    let ip_str = unsafe {
        match ffi_helpers::c_str_to_string(ip_address) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("blkbox_get_ip_sessions: failed to parse IP: {}", e);
                return -1;
            }
        }
    };

    // Query sessions from database
    let db = runtime.db.lock().unwrap();
    let sessions = match db.find_sessions_by_ip(&ip_str) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("blkbox_get_ip_sessions: database error: {}", e);
            return -1;
        }
    };

    // Convert to JSON
    let json = match serde_json::to_string(&sessions) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("blkbox_get_ip_sessions: JSON serialization error: {}", e);
            return -1;
        }
    };

    // Copy to buffer
    let bytes = json.as_bytes();
    if bytes.len() + 1 > buffer_len {
        eprintln!(
            "blkbox_get_ip_sessions: buffer too small (need {}, have {})",
            bytes.len() + 1,
            buffer_len
        );
        return -1;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, bytes.len());
        *buffer.add(bytes.len()) = 0; // Null terminator
    }

    bytes.len() as i32
}

/// Get enriched attack events with all tracking data
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
/// * `limit` - Maximum number of events to retrieve
/// * `offset` - Offset for pagination
/// * `buffer` - Buffer to write JSON array
/// * `buffer_len` - Length of buffer
///
/// # Returns
/// Number of bytes written on success, -1 on error
///
/// # Safety
/// runtime and buffer pointers must be valid
#[no_mangle]
pub extern "C" fn blkbox_get_enriched_attacks(
    runtime: *mut BlkBoxRuntime,
    limit: usize,
    offset: usize,
    buffer: *mut c_char,
    buffer_len: usize,
) -> i32 {
    if runtime.is_null() || buffer.is_null() {
        eprintln!("blkbox_get_enriched_attacks: null pointer");
        return -1;
    }

    let runtime = unsafe { &*runtime };

    // Query enriched attacks
    let db = runtime.db.lock().unwrap();
    let attacks = match db.get_enriched_attacks(limit, offset) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("blkbox_get_enriched_attacks: database error: {}", e);
            return -1;
        }
    };

    // Convert to JSON
    let json = match serde_json::to_string(&attacks) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("blkbox_get_enriched_attacks: JSON serialization error: {}", e);
            return -1;
        }
    };

    // Copy to buffer
    let bytes = json.as_bytes();
    if bytes.len() + 1 > buffer_len {
        eprintln!(
            "blkbox_get_enriched_attacks: buffer too small (need {}, have {})",
            bytes.len() + 1,
            buffer_len
        );
        return -1;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, bytes.len());
        *buffer.add(bytes.len()) = 0; // Null terminator
    }

    bytes.len() as i32
}

/// Get attack events as heap-allocated JSON string
/// Returns a C string that MUST be freed with blkbox_free_string()
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
///
/// # Returns
/// Pointer to heap-allocated JSON string, or null on error
///
/// # Safety
/// runtime pointer must be valid
/// Caller must free the returned string with blkbox_free_string()
#[no_mangle]
pub extern "C" fn blkbox_get_events_json(
    runtime: *mut BlkBoxRuntime,
) -> *mut c_char {
    if runtime.is_null() {
        eprintln!("blkbox_get_events_json: null runtime pointer");
        return ptr::null_mut();
    }

    let runtime = unsafe { &mut *runtime };

    // Drain events from queue
    let events = runtime.drain_events();

    // Convert to JSON
    let json = ffi_helpers::events_to_json(events);

    // Convert to C string (heap-allocated)
    ffi_helpers::string_to_c_str(json)
}

/// Get geolocation for IP as heap-allocated JSON string
/// Returns a C string that MUST be freed with blkbox_free_string()
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
/// * `ip_address` - IP address to geolocate
///
/// # Returns
/// Pointer to heap-allocated JSON string, or null on error
///
/// # Safety
/// runtime pointer must be valid
/// ip_address must be a valid null-terminated string
/// Caller must free the returned string with blkbox_free_string()
#[no_mangle]
pub extern "C" fn blkbox_geolocate_ip_json(
    runtime: *mut BlkBoxRuntime,
    ip_address: *const c_char,
) -> *mut c_char {
    if runtime.is_null() || ip_address.is_null() {
        eprintln!("blkbox_geolocate_ip_json: null pointer");
        return ptr::null_mut();
    }

    let runtime = unsafe { &*runtime };

    let ip_str = unsafe {
        match ffi_helpers::c_str_to_string(ip_address) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("blkbox_geolocate_ip_json: failed to parse IP: {}", e);
                return ptr::null_mut();
            }
        }
    };

    // Perform geolocation lookup
    let geo_data = match tracking::lookup_geolocation(
        &ip_str,
        None,
        &runtime.geoip_reader,
        Some(&runtime.geo_cache),
    ) {
        Some(data) => data,
        None => {
            eprintln!("blkbox_geolocate_ip_json: no geolocation data for IP: {}", ip_str);
            return ptr::null_mut();
        }
    };

    // Convert to JSON
    let json = match serde_json::to_string(&geo_data) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("blkbox_geolocate_ip_json: JSON serialization error: {}", e);
            return ptr::null_mut();
        }
    };

    // Convert to C string (heap-allocated)
    ffi_helpers::string_to_c_str(json)
}

/// Get IP sessions as heap-allocated JSON string
/// Returns a C string that MUST be freed with blkbox_free_string()
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
/// * `ip_address` - IP address to query
///
/// # Returns
/// Pointer to heap-allocated JSON array string, or null on error
///
/// # Safety
/// runtime pointer must be valid
/// ip_address must be a valid null-terminated string
/// Caller must free the returned string with blkbox_free_string()
#[no_mangle]
pub extern "C" fn blkbox_get_ip_sessions_json(
    runtime: *mut BlkBoxRuntime,
    ip_address: *const c_char,
) -> *mut c_char {
    if runtime.is_null() || ip_address.is_null() {
        eprintln!("blkbox_get_ip_sessions_json: null pointer");
        return ptr::null_mut();
    }

    let runtime = unsafe { &*runtime };

    let ip_str = unsafe {
        match ffi_helpers::c_str_to_string(ip_address) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("blkbox_get_ip_sessions_json: failed to parse IP: {}", e);
                return ptr::null_mut();
            }
        }
    };

    // Query sessions from database
    let db = runtime.db.lock().unwrap();
    let sessions = match db.find_sessions_by_ip(&ip_str) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("blkbox_get_ip_sessions_json: database error: {}", e);
            return ptr::null_mut();
        }
    };

    // Convert to JSON
    let json = match serde_json::to_string(&sessions) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("blkbox_get_ip_sessions_json: JSON serialization error: {}", e);
            return ptr::null_mut();
        }
    };

    // Convert to C string (heap-allocated)
    ffi_helpers::string_to_c_str(json)
}

/// Get enriched attacks as heap-allocated JSON string
/// Returns a C string that MUST be freed with blkbox_free_string()
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
/// * `limit` - Maximum number of events to retrieve
/// * `offset` - Offset for pagination
///
/// # Returns
/// Pointer to heap-allocated JSON array string, or null on error
///
/// # Safety
/// runtime pointer must be valid
/// Caller must free the returned string with blkbox_free_string()
#[no_mangle]
pub extern "C" fn blkbox_get_enriched_attacks_json(
    runtime: *mut BlkBoxRuntime,
    limit: usize,
    offset: usize,
) -> *mut c_char {
    if runtime.is_null() {
        eprintln!("blkbox_get_enriched_attacks_json: null pointer");
        return ptr::null_mut();
    }

    let runtime = unsafe { &*runtime };

    // Query enriched attacks
    let db = runtime.db.lock().unwrap();
    let attacks = match db.get_enriched_attacks(limit, offset) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("blkbox_get_enriched_attacks_json: database error: {}", e);
            return ptr::null_mut();
        }
    };

    // Convert to JSON
    let json = match serde_json::to_string(&attacks) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("blkbox_get_enriched_attacks_json: JSON serialization error: {}", e);
            return ptr::null_mut();
        }
    };

    // Convert to C string (heap-allocated)
    ffi_helpers::string_to_c_str(json)
}

/// Free a string returned by BlkBox FFI functions
/// Use this to free strings returned by *_json() functions
///
/// # Arguments
/// * `s` - Pointer to C string returned by BlkBox FFI
///
/// # Safety
/// s must be a valid pointer returned by a BlkBox *_json() function
/// s must not be used after this call
#[no_mangle]
pub extern "C" fn blkbox_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }

    unsafe {
        let _ = std::ffi::CString::from_raw(s);
    }
}

/// Create a session identifier from IP and fingerprint data
/// Returns a JSON string with the session hash and identifier info
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
/// * `ip_address` - IP address as C string
/// * `fingerprints_json` - JSON string of fingerprints as HashMap<String, String>
///
/// # Returns
/// JSON string with session identifier or null on error
///
/// # Safety
/// All pointers must be valid, JSON string must be freed with blkbox_free_string
#[no_mangle]
pub extern "C" fn blkbox_create_session_identifier(
    runtime: *mut BlkBoxRuntime,
    ip_address: *const c_char,
    fingerprints_json: *const c_char,
) -> *mut c_char {
    if runtime.is_null() || ip_address.is_null() || fingerprints_json.is_null() {
        eprintln!("blkbox_create_session_identifier: null pointer");
        return ptr::null_mut();
    }

    let runtime = unsafe { &*runtime };

    // Parse IP address
    let ip = match unsafe { ffi_helpers::c_str_to_string(ip_address) } {
        Ok(s) => s,
        Err(e) => {
            eprintln!("blkbox_create_session_identifier: invalid IP string: {}", e);
            return ptr::null_mut();
        }
    };

    // Parse fingerprints JSON
    let fp_json = match unsafe { ffi_helpers::c_str_to_string(fingerprints_json) } {
        Ok(s) => s,
        Err(e) => {
            eprintln!("blkbox_create_session_identifier: invalid fingerprints JSON: {}", e);
            return ptr::null_mut();
        }
    };

    let fingerprints: HashMap<String, String> = match serde_json::from_str(&fp_json) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("blkbox_create_session_identifier: failed to parse fingerprints: {}", e);
            return ptr::null_mut();
        }
    };

    // Create session identifier using the SessionCorrelator
    let identifier: SessionIdentifier = runtime.session_correlator
        .create_session_identifier(&ip, fingerprints);

    // Serialize to JSON
    let json = match serde_json::to_string(&identifier) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("blkbox_create_session_identifier: JSON serialization error: {}", e);
            return ptr::null_mut();
        }
    };

    ffi_helpers::string_to_c_str(json)
}

/// Get fingerprints for an attack from the database
/// Returns a JSON array of Fingerprint entries
///
/// # Arguments
/// * `runtime` - Pointer to BlkBoxRuntime
/// * `attack_id` - Database ID of the attack
///
/// # Returns
/// JSON string with array of fingerprints or null on error
///
/// # Safety
/// runtime pointer must be valid, returned string must be freed with blkbox_free_string
#[no_mangle]
pub extern "C" fn blkbox_get_attack_fingerprints_json(
    runtime: *mut BlkBoxRuntime,
    attack_id: i64,
) -> *mut c_char {
    if runtime.is_null() {
        eprintln!("blkbox_get_attack_fingerprints_json: null runtime pointer");
        return ptr::null_mut();
    }

    let runtime = unsafe { &*runtime };
    let db = runtime.db.lock().unwrap();

    // Query fingerprints from database using existing helper function
    let fingerprints: Vec<Fingerprint> = match db.with_connection(|conn| {
        crate::storage::operations::get_fingerprints_for_attack(conn, attack_id)
    }) {
        Ok(fps) => fps,
        Err(e) => {
            eprintln!("blkbox_get_attack_fingerprints_json: query error: {}", e);
            return ptr::null_mut();
        }
    };

    // Serialize to JSON
    let json = match serde_json::to_string(&fingerprints) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("blkbox_get_attack_fingerprints_json: JSON serialization error: {}", e);
            return ptr::null_mut();
        }
    };

    ffi_helpers::string_to_c_str(json)
}

/// Free the BlkBox runtime
///
/// # Safety
/// runtime pointer must be valid and not used after this call
#[no_mangle]
pub extern "C" fn blkbox_free(runtime: *mut BlkBoxRuntime) {
    if runtime.is_null() {
        return;
    }

    unsafe {
        let _ = Box::from_raw(runtime);
    }

    println!("BlkBox runtime freed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_creation() {
        let runtime = blkbox_init();
        assert!(!runtime.is_null());
        blkbox_free(runtime);
    }

    #[test]
    fn test_service_lifecycle() {
        let runtime = blkbox_init();
        assert!(!runtime.is_null());

        let config = std::ffi::CString::new(r#"{"enabled":true}"#).unwrap();

        let service_id = blkbox_start_honeypot(
            runtime,
            ServiceType::HTTP as u8,
            8080,
            config.as_ptr(),
        );

        assert!(service_id > 0);

        let result = blkbox_stop_honeypot(runtime, service_id as u32);
        assert_eq!(result, 0);

        blkbox_free(runtime);
    }
}
