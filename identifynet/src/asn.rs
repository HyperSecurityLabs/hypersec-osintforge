/// ASN (Autonomous System Number) lookup via MaxMind GeoLite2-ASN database.
use crate::models::AsnInfo;
use std::net::IpAddr;
use std::path::Path;

/// Look up ASN information for the given IP address.
///
/// Opens the MaxMind ASN database at `db_path`, performs a lookup,
/// and returns the AS number and organization if found.
pub fn lookup(ip: IpAddr, db_path: &Path) -> Option<AsnInfo> {
    // Check: database file must exist
    if !db_path.exists() {
        return None;
    }

    // Step: open the MaxMind database reader
    let reader = match maxminddb::Reader::open_readfile(db_path) {
        Ok(r) => r,
        Err(_) => return None,
    };

    // Step: perform the ASN lookup
    let result: Result<maxminddb::geoip2::Asn, _> = reader.lookup(ip);
    // Handle: map the result into our AsnInfo model
    match result {
        Ok(asn) => {
            let mut info = AsnInfo::default();
            info.number = asn.autonomous_system_number;
            info.organization = asn.autonomous_system_organization.map(|s| s.to_string());
            Some(info)
        }
        Err(_) => None,
    }
}
