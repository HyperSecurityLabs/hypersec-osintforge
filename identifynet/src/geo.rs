/// Geographic location lookup via MaxMind GeoLite2-City database.
use crate::models::GeoInfo;
use std::net::IpAddr;
use std::path::Path;

/// Look up geographic information for the given IP address.
///
/// Opens the MaxMind City database at `db_path`, performs a lookup,
/// and returns city, state, country, postal code, coordinates, and timezone.
pub fn lookup(ip: IpAddr, db_path: &Path) -> Option<GeoInfo> {
    // Check: database file must exist
    if !db_path.exists() {
        return None;
    }

    // Step: open the MaxMind database reader
    let reader = match maxminddb::Reader::open_readfile(db_path) {
        Ok(r) => r,
        Err(_) => return None,
    };

    // Step: perform the City database lookup
    let result: Result<maxminddb::geoip2::City, _> = reader.lookup(ip);
    // Handle: map the result into our GeoInfo model
    match result {
        Ok(city) => {
            let mut info = GeoInfo::default();

            // Handle: extract location data (lat, lon, timezone)
            if let Some(loc) = city.location {
                info.latitude = loc.latitude;
                info.longitude = loc.longitude;
                info.timezone = loc.time_zone.map(|s| s.to_string());
            }

            // Handle: extract city name
            if let Some(c) = city.city {
                if let Some(names) = c.names {
                    info.city = names.get("en").map(|s| s.to_string());
                }
            }

            // Handle: extract state / region from subdivisions
            if let Some(ref subs) = city.subdivisions {
                if let Some(sub) = subs.first() {
                    if let Some(ref names) = sub.names {
                        info.state = names.get("en").map(|s| s.to_string());
                    }
                }
            }

            // Handle: extract country name and ISO code
            if let Some(c) = city.country {
                if let Some(names) = c.names {
                    info.country = names.get("en").map(|s| s.to_string());
                }
                info.country_code = c.iso_code.map(|s| s.to_string());
            }

            // Handle: extract postal code
            if let Some(p) = city.postal {
                info.postal = p.code.map(|s| s.to_string());
            }

            Some(info)
        }
        Err(_) => None,
    }
}
