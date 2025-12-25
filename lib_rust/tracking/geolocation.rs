// Geolocation module for IP tracking and real IP extraction

use crate::storage::models::{GeolocationData, GeoSource, CloudflareMetadata};
use axum::http::HeaderMap;
use maxminddb::{geoip2, Reader};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Extract the real IP address from request headers or socket address
/// Priority order: CF-Connecting-IP -> X-Forwarded-For -> X-Real-IP -> Direct socket
pub fn extract_real_ip(headers: &HeaderMap, socket_addr: &str) -> String {
    // Priority 1: Cloudflare CF-Connecting-IP (most reliable when behind CF)
    if let Some(cf_ip) = headers.get("cf-connecting-ip") {
        if let Ok(ip_str) = cf_ip.to_str() {
            if is_valid_ip(ip_str) {
                return ip_str.to_string();
            }
        }
    }

    // Priority 2: X-Forwarded-For (take the first/leftmost IP)
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
            // We want the leftmost (original client) IP
            let first_ip = xff_str.split(',').next().unwrap_or("").trim();
            if is_valid_ip(first_ip) {
                return first_ip.to_string();
            }
        }
    }

    // Priority 3: X-Real-IP
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if is_valid_ip(ip_str) {
                return ip_str.to_string();
            }
        }
    }

    // Priority 4: Direct socket address (fallback)
    // Socket address might be in format "ip:port", extract just the IP
    socket_addr.split(':').next().unwrap_or(socket_addr).to_string()
}

/// Validate if a string is a valid IP address
fn is_valid_ip(ip_str: &str) -> bool {
    ip_str.parse::<IpAddr>().is_ok()
}

/// Extract Cloudflare metadata from request headers
pub fn extract_cloudflare_metadata(headers: &HeaderMap) -> Option<CloudflareMetadata> {
    CloudflareMetadata::from_headers(headers)
}

/// MaxMind GeoIP reader wrapper
pub struct GeoIpReader {
    city_reader: Option<Reader<Vec<u8>>>,
    asn_reader: Option<Reader<Vec<u8>>>,
}

impl GeoIpReader {
    /// Create a new GeoIP reader with MaxMind database files
    pub fn new(city_db_path: Option<&str>, asn_db_path: Option<&str>) -> Self {
        let city_reader = city_db_path.and_then(|path| {
            if Path::new(path).exists() {
                Reader::open_readfile(path).ok()
            } else {
                tracing::warn!("GeoIP city database not found at: {}", path);
                None
            }
        });

        let asn_reader = asn_db_path.and_then(|path| {
            if Path::new(path).exists() {
                Reader::open_readfile(path).ok()
            } else {
                tracing::warn!("GeoIP ASN database not found at: {}", path);
                None
            }
        });

        Self {
            city_reader,
            asn_reader,
        }
    }

    /// Lookup geolocation data for an IP address
    pub fn lookup(&self, ip: &str) -> Option<GeolocationData> {
        let ip_addr: IpAddr = ip.parse().ok()?;

        let mut geo_data = GeolocationData {
            ip: ip.to_string(),
            country_code: None,
            country_name: None,
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            postal_code: None,
            timezone: None,
            asn: None,
            isp: None,
            organization: None,
            is_anonymous_proxy: false,
            is_satellite_provider: false,
            source: GeoSource::MaxMind,
        };

        // Lookup city/location data
        if let Some(reader) = &self.city_reader {
            if let Ok(city) = reader.lookup::<geoip2::City>(ip_addr) {
                // Country data
                if let Some(country) = city.country {
                    geo_data.country_code = country.iso_code.map(|s| s.to_string());
                    geo_data.country_name = country.names
                        .and_then(|names| names.get("en").map(|s| s.to_string()));
                }

                // Subdivision (region/state)
                if let Some(subdivisions) = city.subdivisions {
                    if let Some(subdivision) = subdivisions.first() {
                        geo_data.region = subdivision.names
                            .as_ref()
                            .and_then(|names| names.get("en").map(|s| s.to_string()));
                    }
                }

                // City
                if let Some(city_info) = city.city {
                    geo_data.city = city_info.names
                        .and_then(|names| names.get("en").map(|s| s.to_string()));
                }

                // Location (lat/lon)
                if let Some(location) = city.location {
                    geo_data.latitude = location.latitude;
                    geo_data.longitude = location.longitude;
                    geo_data.timezone = location.time_zone.map(|s| s.to_string());
                }

                // Postal code
                if let Some(postal) = city.postal {
                    geo_data.postal_code = postal.code.map(|s| s.to_string());
                }

                // Traits (proxy detection)
                if let Some(traits) = city.traits {
                    geo_data.is_anonymous_proxy = traits.is_anonymous_proxy.unwrap_or(false);
                    geo_data.is_satellite_provider = traits.is_satellite_provider.unwrap_or(false);
                }
            }
        }

        // Lookup ASN data
        if let Some(reader) = &self.asn_reader {
            if let Ok(asn) = reader.lookup::<geoip2::Asn>(ip_addr) {
                geo_data.asn = asn.autonomous_system_number;
                geo_data.isp = asn.autonomous_system_organization.map(|s| s.to_string());
                geo_data.organization = asn.autonomous_system_organization.map(|s| s.to_string());
            }
        }

        // Return None if we got no useful data
        if geo_data.country_code.is_none() && geo_data.asn.is_none() {
            None
        } else {
            Some(geo_data)
        }
    }
}

/// Cached geolocation entry
#[derive(Clone)]
struct CachedGeoData {
    data: GeolocationData,
    cached_at: Instant,
}

/// Geolocation cache with TTL
pub struct GeolocationCache {
    cache: Arc<Mutex<HashMap<String, CachedGeoData>>>,
    ttl: Duration,
}

impl GeolocationCache {
    /// Create a new geolocation cache with specified TTL
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            ttl,
        }
    }

    /// Create a cache with default 1-hour TTL
    pub fn with_default_ttl() -> Self {
        Self::new(Duration::from_secs(3600))
    }

    /// Get cached geolocation data if still valid
    pub fn get(&self, ip: &str) -> Option<GeolocationData> {
        let cache = self.cache.lock().unwrap();
        if let Some(cached) = cache.get(ip) {
            if cached.cached_at.elapsed() < self.ttl {
                return Some(cached.data.clone());
            }
        }
        None
    }

    /// Store geolocation data in cache
    pub fn set(&self, ip: String, data: GeolocationData) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(ip, CachedGeoData {
            data,
            cached_at: Instant::now(),
        });
    }

    /// Clear expired entries from cache
    pub fn cleanup(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.retain(|_, cached| cached.cached_at.elapsed() < self.ttl);
    }

    /// Get cache statistics
    pub fn stats(&self) -> (usize, usize) {
        let cache = self.cache.lock().unwrap();
        let total = cache.len();
        let valid = cache.values()
            .filter(|cached| cached.cached_at.elapsed() < self.ttl)
            .count();
        (total, valid)
    }
}

/// Main geolocation lookup function with Cloudflare header priority
pub fn lookup_geolocation(
    ip: &str,
    cloudflare_metadata: Option<&CloudflareMetadata>,
    geoip_reader: &GeoIpReader,
    cache: Option<&GeolocationCache>,
) -> Option<GeolocationData> {
    // Check cache first
    if let Some(cache) = cache {
        if let Some(cached_data) = cache.get(ip) {
            tracing::debug!("Geolocation cache hit for IP: {}", ip);
            return Some(cached_data);
        }
    }

    let mut geo_data = None;

    // Priority 1: Use Cloudflare CF-IPCountry header if available
    if let Some(cf) = cloudflare_metadata {
        if let Some(country_code) = &cf.cf_ipcountry {
            // Create basic geo data from Cloudflare header
            geo_data = Some(GeolocationData {
                ip: ip.to_string(),
                country_code: Some(country_code.clone()),
                country_name: None, // CF doesn't provide full country name
                region: None,
                city: None,
                latitude: None,
                longitude: None,
                postal_code: None,
                timezone: None,
                asn: None,
                isp: None,
                organization: None,
                is_anonymous_proxy: false,
                is_satellite_provider: false,
                source: GeoSource::Cloudflare,
            });

            tracing::debug!("Using Cloudflare geolocation for IP: {} (country: {})", ip, country_code);
        }
    }

    // Priority 2: Use MaxMind database for detailed lookup
    // (or to supplement CF data with more details)
    if let Some(maxmind_data) = geoip_reader.lookup(ip) {
        if let Some(cf_data) = geo_data {
            // Merge: Keep CF country code but add MaxMind details
            geo_data = Some(GeolocationData {
                ip: maxmind_data.ip,
                country_code: cf_data.country_code, // Keep CF country
                country_name: maxmind_data.country_name,
                region: maxmind_data.region,
                city: maxmind_data.city,
                latitude: maxmind_data.latitude,
                longitude: maxmind_data.longitude,
                postal_code: maxmind_data.postal_code,
                timezone: maxmind_data.timezone,
                asn: maxmind_data.asn,
                isp: maxmind_data.isp,
                organization: maxmind_data.organization,
                is_anonymous_proxy: maxmind_data.is_anonymous_proxy,
                is_satellite_provider: maxmind_data.is_satellite_provider,
                source: GeoSource::Hybrid, // Both sources
            });
        } else {
            // No CF data, use MaxMind only
            geo_data = Some(maxmind_data);
        }

        tracing::debug!("MaxMind geolocation lookup for IP: {}", ip);
    }

    // Cache the result if we got data
    if let (Some(data), Some(cache)) = (&geo_data, cache) {
        cache.set(ip.to_string(), data.clone());
    }

    geo_data
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_real_ip_cloudflare() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("1.2.3.4"));
        headers.insert("x-forwarded-for", HeaderValue::from_static("5.6.7.8"));

        let ip = extract_real_ip(&headers, "127.0.0.1:8080");
        assert_eq!(ip, "1.2.3.4"); // CF takes priority
    }

    #[test]
    fn test_extract_real_ip_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4, 5.6.7.8, 9.10.11.12"));

        let ip = extract_real_ip(&headers, "127.0.0.1:8080");
        assert_eq!(ip, "1.2.3.4"); // First IP in chain
    }

    #[test]
    fn test_extract_real_ip_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("1.2.3.4"));

        let ip = extract_real_ip(&headers, "127.0.0.1:8080");
        assert_eq!(ip, "1.2.3.4");
    }

    #[test]
    fn test_extract_real_ip_socket_fallback() {
        let headers = HeaderMap::new();
        let ip = extract_real_ip(&headers, "1.2.3.4:8080");
        assert_eq!(ip, "1.2.3.4"); // Extracted from socket address
    }

    #[test]
    fn test_is_valid_ip() {
        assert!(is_valid_ip("1.2.3.4"));
        assert!(is_valid_ip("::1"));
        assert!(is_valid_ip("2001:db8::1"));
        assert!(!is_valid_ip("not-an-ip"));
        assert!(!is_valid_ip("999.999.999.999"));
    }

    #[test]
    fn test_geolocation_cache() {
        let cache = GeolocationCache::new(Duration::from_secs(1));

        let geo_data = GeolocationData {
            ip: "1.2.3.4".to_string(),
            country_code: Some("US".to_string()),
            country_name: Some("United States".to_string()),
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            postal_code: None,
            timezone: None,
            asn: None,
            isp: None,
            organization: None,
            is_anonymous_proxy: false,
            is_satellite_provider: false,
            source: GeoSource::MaxMind,
        };

        // Store in cache
        cache.set("1.2.3.4".to_string(), geo_data.clone());

        // Should retrieve from cache
        let cached = cache.get("1.2.3.4");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().country_code, Some("US".to_string()));

        // Wait for expiry
        std::thread::sleep(Duration::from_secs(2));
        let expired = cache.get("1.2.3.4");
        assert!(expired.is_none());
    }

    #[test]
    fn test_cache_stats() {
        let cache = GeolocationCache::new(Duration::from_secs(60));

        let geo_data = GeolocationData {
            ip: "1.2.3.4".to_string(),
            country_code: Some("US".to_string()),
            country_name: None,
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            postal_code: None,
            timezone: None,
            asn: None,
            isp: None,
            organization: None,
            is_anonymous_proxy: false,
            is_satellite_provider: false,
            source: GeoSource::MaxMind,
        };

        cache.set("1.2.3.4".to_string(), geo_data.clone());
        cache.set("5.6.7.8".to_string(), geo_data.clone());

        let (total, valid) = cache.stats();
        assert_eq!(total, 2);
        assert_eq!(valid, 2);
    }
}
