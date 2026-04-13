use std::fmt;

use time::{OffsetDateTime, UtcOffset};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;

const AUDIT_TIME_OFFSET_HOURS: i8 = 8;
const AUDIT_TIME_OFFSET_LABEL: &str = "UTC+8";

#[derive(Clone, Copy, Debug, Default)]
struct AuditLogTimer;

impl FormatTime for AuditLogTimer {
    fn format_time(&self, writer: &mut Writer<'_>) -> fmt::Result {
        write!(
            writer,
            "{}",
            format_offset_datetime(OffsetDateTime::now_utc())
        )
    }
}

pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_timer(AuditLogTimer)
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}

#[must_use]
pub fn format_unix_timestamp_secs(timestamp_secs: u64) -> String {
    i64::try_from(timestamp_secs)
        .ok()
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .map(format_offset_datetime)
        .unwrap_or_else(|| format!("{timestamp_secs} ({AUDIT_TIME_OFFSET_LABEL})"))
}

fn format_offset_datetime(timestamp: OffsetDateTime) -> String {
    let timestamp = timestamp.to_offset(audit_time_offset());

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} ({AUDIT_TIME_OFFSET_LABEL})",
        timestamp.year(),
        timestamp.month() as u8,
        timestamp.day(),
        timestamp.hour(),
        timestamp.minute(),
        timestamp.second(),
        timestamp.nanosecond() / 1_000_000,
    )
}

fn audit_time_offset() -> UtcOffset {
    UtcOffset::from_hms(AUDIT_TIME_OFFSET_HOURS, 0, 0)
        .expect("audit log UTC offset should stay valid")
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::{format_offset_datetime, format_unix_timestamp_secs};

    #[test]
    fn formats_unix_seconds_in_audit_timezone() {
        assert_eq!(
            format_unix_timestamp_secs(0),
            "1970-01-01 08:00:00.000 (UTC+8)"
        );
    }

    #[test]
    fn formats_offset_datetimes_with_millisecond_precision() {
        let timestamp = OffsetDateTime::from_unix_timestamp_nanos(1_234_567_890_000_000).unwrap();

        assert_eq!(
            format_offset_datetime(timestamp),
            "1970-01-15 14:56:07.890 (UTC+8)"
        );
    }
}
