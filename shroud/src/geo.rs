/// Shroud — Geolocation & ASN Lookup
///
/// Queries ip-api.com for geographic location, organization, ISP,
/// and ASN information for discovered network nodes.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use std::net::IpAddr;
use std::time::Duration;
use crate::models::GeoInfo;

/// Looks up geolocation and ASN data for an IP address via ip-api.com.
pub async fn geo_lookup(ip: IpAddr) -> Option<GeoInfo> {
    let url = format!(
        "http://ip-api.com/json/{}?fields=city,regionName,country,org,isp,as,asname,status",
        ip
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;
    let resp = client.get(&url).send().await.ok()?;
    let data: serde_json::Value = resp.json().await.ok()?;
    if data.get("status").and_then(|v| v.as_str()) == Some("success") {
        Some(GeoInfo {
            city: data.get("city").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            region: data.get("regionName").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            country: data.get("country").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            org: data.get("org").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            asn: data.get("as").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            as_org: data.get("asname").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            isp: data.get("isp").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        })
    } else {
        None
    }
}
