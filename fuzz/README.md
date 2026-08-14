# Archive Fuzzing

The fuzz package is excluded from the main Cargo workspace so normal stable
builds do not require libFuzzer or a nightly toolchain.

Install the runner and execute either target from the repository root:

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
cargo +nightly fuzz run archive_path -- -max_total_time=60
cargo +nightly fuzz run archive_preflight -- -max_len=1048576 -max_total_time=300
cargo +nightly fuzz run pak_inventory -- -max_len=65536 -max_total_time=300
```

`archive_path` exercises cross-platform member-path validation. The
`archive_preflight` target bounds inputs to 1 MiB, tests raw bytes, and also
injects ZIP or 7z magic so mutations reach both parsers more often. A crash,
panic, timeout, or sanitizer finding is a failure; ordinary parser errors are
expected for hostile inputs.

`pak_inventory` bounds inputs to 64 KiB and alternates raw hostile bytes, valid
generated V11 PAKs, and single-byte mutations across generated PAK structure and
payload. Oodle and encryption are not enabled in the fuzz package.

CI should run bounded smoke sessions for both targets once this directory is
hosted in a Git repository. Longer fuzzing campaigns should preserve minimized
regressions as deterministic tests in `crates/rrmm-archive/tests/`.
