//! Small time helpers. Unix epoch seconds are the storage format everywhere;
//! RFC3339 is produced only for human-facing output (reports, CLI).

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

pub fn now_ms() -> i128 {
    let t = OffsetDateTime::now_utc();
    i128::from(t.unix_timestamp()) * 1000 + i128::from(t.nanosecond() / 1_000_000)
}

pub fn rfc3339(ts: i64) -> String {
    match OffsetDateTime::from_unix_timestamp(ts) {
        Ok(t) => t.format(&Rfc3339).unwrap_or_else(|_| ts.to_string()),
        Err(_) => ts.to_string(),
    }
}

pub fn rfc3339_now() -> String {
    rfc3339(now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_epoch() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert!(now() > 1_700_000_000);
        assert_eq!(rfc3339(-1), "1969-12-31T23:59:59Z");
    }
}
