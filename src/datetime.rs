//! UTC dates and the existing RFC 3339 wire format, backed by Jiff.

use jiff::{civil::Date, tz::Offset, tz::TimeZone, Timestamp};

pub(crate) fn today_utc() -> Date {
    date_utc(Timestamp::now())
}

fn date_utc(timestamp: Timestamp) -> Date {
    timestamp.to_zoned_datetime(TimeZone::UTC).date()
}

pub(crate) fn now_rfc3339() -> String {
    format_rfc3339(Timestamp::now())
}

fn format_rfc3339(timestamp: Timestamp) -> String {
    // Preserve Chrono's AutoSi precision and explicit +00:00 offset used in
    // receipts and VEX documents, including millisecond/microsecond clocks.
    let nanos = timestamp.subsec_nanosecond();
    let precision = if nanos == 0 {
        0
    } else if nanos % 1_000_000 == 0 {
        3
    } else if nanos % 1_000 == 0 {
        6
    } else {
        9
    };
    format!("{:.precision$}", timestamp.display_with_offset(Offset::UTC))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_timestamp_keeps_offset_and_fractional_precision() {
        for (input, expected) in [
            ("2026-02-28T23:59:59Z", "2026-02-28T23:59:59+00:00"),
            ("2026-02-28T23:59:59.123Z", "2026-02-28T23:59:59.123+00:00"),
            (
                "2026-02-28T23:59:59.123456Z",
                "2026-02-28T23:59:59.123456+00:00",
            ),
            (
                "2026-02-28T23:59:59.123456789Z",
                "2026-02-28T23:59:59.123456789+00:00",
            ),
            ("1969-12-31T23:59:59.999Z", "1969-12-31T23:59:59.999+00:00"),
        ] {
            let timestamp: Timestamp = input.parse().unwrap();
            let actual = format_rfc3339(timestamp);
            assert_eq!(actual, expected);
            assert_eq!(actual.parse::<Timestamp>().unwrap(), timestamp);
        }
    }

    #[test]
    fn policy_today_uses_utc_across_offset_and_leap_day_boundaries() {
        for (input, expected) in [
            ("2024-03-01T00:30:00+01:00", "2024-02-29"),
            ("2024-02-29T23:30:00-01:00", "2024-03-01"),
            ("2026-01-01T00:30:00+01:00", "2025-12-31"),
        ] {
            assert_eq!(date_utc(input.parse().unwrap()).to_string(), expected);
        }
    }

    #[test]
    fn current_timestamp_and_policy_date_are_bounded_by_the_clock_reads() {
        let before = Timestamp::now();
        let timestamp: Timestamp = now_rfc3339().parse().unwrap();
        let today = today_utc();
        let after = Timestamp::now();
        assert!(before <= timestamp && timestamp <= after);
        assert!(date_utc(before) <= today && today <= date_utc(after));
    }
}
