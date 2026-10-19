# Change Log

## v1.1.1

First release.

## v2.0.0

- Add `-f/--file` argument, to inspect permissions and Unix file types without following symlinks; reject --json and exit with an error on access failure.
- Convert Unix mode bits through Octal::from(u32), preserving special permissions and masking out file type bits.

**Breaking Changes:**

Replace `Octal::from_str` with `TryFrom<&str>.` Callers must use `Octal::try_from(...)` or `.try_into()` instead. This adopts Rust’s standard trait for fallible conversions.

**Credit:** @Sisyphus1813
