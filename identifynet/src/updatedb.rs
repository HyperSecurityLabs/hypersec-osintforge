/// MaxMind GeoIP database downloader and updater.
///
/// Downloads GeoLite2 City and ASN databases from MaxMind, extracts the
/// `.mmdb` files from the tarball archive, and places them at the requested paths.
use crate::stealth::random_ua;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Base URL for downloading the GeoLite2-City database.
const CITY_URL: &str =
    "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=";
/// Base URL for downloading the GeoLite2-ASN database.
const ASN_URL: &str =
    "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=";
/// Common query suffix for tar.gz format.
const SUFFIX: &str = "&suffix=tar.gz";

/// Represents the status of a database file check or download.
pub enum DbStatus {
    /// Database already exists on disk.
    Present,
    /// Database was freshly downloaded.
    Downloaded,
    /// Database is missing and could not be downloaded (with reason).
    Missing(String),
}

/// Ensure both GeoIP databases exist, downloading them if necessary.
///
/// Returns a tuple of `(geo_status, asn_status)`.
pub fn ensure(geo_path: &Path, asn_path: &Path, license_key: Option<&str>) -> (DbStatus, DbStatus) {
    let geo_status = check_one(geo_path, "GeoLite2-City", license_key);
    let asn_status = check_one(asn_path, "GeoLite2-ASN", license_key);
    (geo_status, asn_status)
}

/// Check whether a single database exists; download it if a license key is available.
fn check_one(path: &Path, name: &str, license_key: Option<&str>) -> DbStatus {
    // Check: database already present on disk
    if path.exists() {
        return DbStatus::Present;
    }

    // Check: ensure we have a license key to download
    let key = match license_key {
        Some(k) if !k.is_empty() => k,
        _ => {
            return DbStatus::Missing(format!(
                "{} not found. Set MAXMIND_LICENSE_KEY or use --maxmind-key to auto-download",
                name
            ));
        }
    };

    // Step: build the download URL
    let url = match name {
        "GeoLite2-City" => format!("{}{}{}", CITY_URL, key, SUFFIX),
        "GeoLite2-ASN" => format!("{}{}{}", ASN_URL, key, SUFFIX),
        _ => return DbStatus::Missing(format!("Unknown database: {}", name)),
    };

    // Step: attempt download and extraction
    match download_and_extract(&url, path, name) {
        Ok(()) => DbStatus::Downloaded,
        Err(e) => DbStatus::Missing(format!("Download failed for {}: {}", name, e)),
    }
}

/// Download a tar.gz archive and extract the `.mmdb` file to the target path.
fn download_and_extract(url: &str, out_path: &Path, name: &str) -> Result<(), String> {
    // Step: create a temporary directory for the download
    let tmp_dir = PathBuf::from(format!(
        "/tmp/identifynet_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&tmp_dir).map_err(|e| format!("temp dir: {}", e))?;

    let tar_path = tmp_dir.join(format!("{}.tar.gz", name));

    // Step: build HTTP client with 120s timeout and random User-Agent
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent(random_ua())
        .build()
        .map_err(|e| format!("http client: {}", e))?;

    // Step: send download request
    let resp = client
        .get(url)
        .send()
        .map_err(|e| format!("download: {}", e))?;

    // Check: verify HTTP success status
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(format!("HTTP {}: {}", status, body.trim().chars().take(200).collect::<String>()));
    }

    // Step: read response bytes and write to temp file
    let bytes = resp.bytes().map_err(|e| format!("read response: {}", e))?;
    fs::write(&tar_path, &bytes).map_err(|e| format!("write temp: {}", e))?;

    // Step: open the tar.gz and decompress
    let tar_file = fs::File::open(&tar_path).map_err(|e| format!("open temp: {}", e))?;
    let decoder = flate2::read::GzDecoder::new(tar_file);
    let mut archive = tar::Archive::new(decoder);

    // Step: ensure parent output directory exists
    let parent = out_path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|e| format!("create dir: {}", e))?;

    // Step: iterate archive entries to find the .mmdb file
    for entry in archive.entries().map_err(|e| format!("read archive: {}", e))? {
        let mut entry = entry.map_err(|e| format!("archive entry: {}", e))?;
        if let Ok(name) = entry.path() {
            // Check: only extract the .mmdb file
            if name.ends_with(".mmdb") {
                entry
                    .unpack(out_path)
                    .map_err(|e| format!("extract mmdb: {}", e))?;
                break;
            }
        }
    }

    // Step: clean up temporary directory
    let _ = fs::remove_dir_all(&tmp_dir);

    // Check: verify the .mmdb file was extracted
    if out_path.exists() {
        Ok(())
    } else {
        Err("extraction produced no .mmdb file".to_string())
    }
}
