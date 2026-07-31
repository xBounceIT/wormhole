//! GUID format `D` and .NET round-trip timestamp (`O`) helpers.

use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use uuid::Uuid;

use crate::{Result, StorageError};

/// Format a UUID as .NET Guid format `D` (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, lowercase).
pub fn format_guid_d(id: Uuid) -> String {
    wormhole_domain::format_guid_d(&id)
}

/// Parse a GUID stored as .NET format `D` (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
///
/// Accepts ASCII case variants of format `D` only. Rejects empty/whitespace,
/// format `N` (32 hex), braced, and URN forms — writers always emit lowercase `D`.
pub fn parse_guid_d(value: &str) -> Result<Uuid> {
    let trimmed = value.trim();
    if !is_guid_format_d(trimmed) {
        return Err(StorageError::InvalidGuid {
            value: value.to_owned(),
            message: "expected .NET format D (8-4-4-4-12 hex)".into(),
        });
    }
    Uuid::try_parse(trimmed).map_err(|e| StorageError::InvalidGuid {
        value: value.to_owned(),
        message: e.to_string(),
    })
}

/// True when `value` matches format `D` shape (8-4-4-4-12 hex + hyphens), any ASCII case.
fn is_guid_format_d(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() != 36 {
        return false;
    }
    if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            continue;
        }
        if !c.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Format UTC time as .NET `DateTime.UtcNow.ToString("O")`-compatible text
/// (`yyyy-MM-ddTHH:mm:ss.fffffffZ`).
pub fn format_timestamp_o(dt: DateTime<Utc>) -> String {
    // .NET "O" for DateTime Kind=Utc uses up to 7 fractional digits and a trailing Z.
    let nanos = dt.timestamp_subsec_nanos();
    let frac7 = nanos / 100; // 100 ns ticks → 7 digits
    format!("{}.{:07}Z", dt.format("%Y-%m-%dT%H:%M:%S"), frac7)
}

/// Parse a timestamp written by C# round-trip `O` / ISO text columns.
pub fn parse_timestamp_o(value: &str) -> Result<DateTime<Utc>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(StorageError::InvalidTimestamp {
            value: value.to_owned(),
            message: "empty timestamp".into(),
        });
    }

    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(dt.with_timezone(&Utc));
    }

    // DateTimeOffset "O" sometimes lacks a colon in the offset on older writers — try FixedOffset.
    if let Ok(dt) = DateTime::<FixedOffset>::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S%.f%z") {
        return Ok(dt.with_timezone(&Utc));
    }

    // Microsoft.Data.Sqlite may emit space-separated local/UTC forms.
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, fmt) {
            return Ok(naive.and_utc());
        }
    }

    // Strip trailing Z and re-parse as naive UTC (covers odd fractional widths).
    let without_z = trimmed.strip_suffix('Z').unwrap_or(trimmed);
    if let Ok(naive) = NaiveDateTime::parse_from_str(without_z, "%Y-%m-%dT%H:%M:%S%.f") {
        return Ok(naive.and_utc());
    }

    Err(StorageError::InvalidTimestamp {
        value: value.to_owned(),
        message: "unrecognized .NET O / ISO timestamp".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_d_round_trip() {
        let id = Uuid::parse_str("a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91").unwrap();
        let s = format_guid_d(id);
        assert_eq!(s, "a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91");
        assert_eq!(parse_guid_d(&s).unwrap(), id);
        assert_eq!(
            parse_guid_d("A7F3C1E2-9B6D-4E8A-BF21-7C0D2E5A4B91").unwrap(),
            id
        );
    }

    #[test]
    fn guid_d_rejects_malformed_and_non_d_forms() {
        for bad in [
            "",
            "   ",
            "not-a-guid",
            "a7f3c1e29b6d4e8abf217c0d2e5a4b91",              // format N
            "{a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91}",      // braced
            "urn:uuid:a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91",
            "a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b9",         // truncated
            "a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91Z",      // trailing junk
        ] {
            assert!(
                parse_guid_d(bad).is_err(),
                "expected reject for {bad:?}"
            );
        }
    }

    #[test]
    fn timestamp_o_utc_round_trip() {
        let dt = DateTime::parse_from_rfc3339("2026-07-31T10:18:44.1234567Z")
            .unwrap()
            .with_timezone(&Utc);
        let s = format_timestamp_o(dt);
        assert_eq!(s, "2026-07-31T10:18:44.1234567Z");
        let parsed = parse_timestamp_o(&s).unwrap();
        assert_eq!(parsed, dt);
        assert_eq!(parsed.timestamp_subsec_nanos(), dt.timestamp_subsec_nanos());
    }

    #[test]
    fn timestamp_parses_offset_o() {
        let parsed = parse_timestamp_o("2026-07-31T12:18:44.1234567+02:00").unwrap();
        let utc = DateTime::parse_from_rfc3339("2026-07-31T10:18:44.1234567Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(parsed, utc);
    }

    #[test]
    fn timestamp_parses_space_separated_dotnet_sqlite_form() {
        let parsed = parse_timestamp_o("2026-07-31 10:18:44.1234567").unwrap();
        let expected = parse_timestamp_o("2026-07-31T10:18:44.1234567Z").unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn timestamp_rejects_empty_and_garbage() {
        assert!(parse_timestamp_o("").is_err());
        assert!(parse_timestamp_o("   ").is_err());
        assert!(parse_timestamp_o("not-a-date").is_err());
    }
}
