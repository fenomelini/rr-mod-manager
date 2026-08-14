use rrmm_archive::{ArchiveLimits, extract_archive_to_staging, preflight_archive, preflight_zip};
use std::fs::{self, File};
use std::io::{Cursor, Write};
use std::path::Path;
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

#[test]
fn common_seven_zip_codecs_preflight_and_extract() {
    let temporary = TempDir::new().unwrap();
    let methods = [
        sevenz_rust2::EncoderMethod::COPY,
        sevenz_rust2::EncoderMethod::LZMA,
        sevenz_rust2::EncoderMethod::LZMA2,
        sevenz_rust2::EncoderMethod::PPMD,
        sevenz_rust2::EncoderMethod::BZIP2,
        sevenz_rust2::EncoderMethod::DEFLATE,
    ];

    for method in methods {
        let archive = temporary.path().join(format!("{}.7z", method.name()));
        let staging = temporary.path().join(format!("staging-{}", method.name()));
        write_seven_zip(&archive, method);

        let report = preflight_archive(&archive, &ArchiveLimits::default()).unwrap();
        assert!(report.accepted, "{} was rejected", method.name());
        extract_archive_to_staging(&archive, &staging, &ArchiveLimits::default()).unwrap();
        assert_eq!(
            fs::read(staging.join("Example_P.pak")).unwrap(),
            b"pak fixture"
        );
    }
}

#[test]
fn unsupported_seven_zip_codec_is_rejected_during_preflight() {
    let temporary = TempDir::new().unwrap();
    let archive = temporary.path().join("unsupported.7z");
    write_seven_zip(&archive, sevenz_rust2::EncoderMethod::LZMA2);
    replace_plain_header_lzma2_with_unknown_method(&archive);

    let report = preflight_archive(&archive, &ArchiveLimits::default()).unwrap();

    assert!(!report.accepted);
    assert!(
        report
            .rejections
            .iter()
            .any(|rejection| rejection.code == "unsupported_codec")
    );
}

#[test]
fn truncated_zip_and_seven_zip_corpus_never_creates_staging() {
    let temporary = TempDir::new().unwrap();
    let valid_zip = temporary.path().join("valid.zip");
    let valid_seven_zip = temporary.path().join("valid.7z");
    write_zip(&valid_zip, b"pak fixture", CompressionMethod::Stored);
    let source = temporary.path().join("Example_P.pak");
    fs::write(&source, b"pak fixture").unwrap();
    sevenz_rust2::compress_to_path(&source, &valid_seven_zip).unwrap();

    for (format, bytes) in [
        ("zip", fs::read(valid_zip).unwrap()),
        ("7z", fs::read(valid_seven_zip).unwrap()),
    ] {
        let cuts = [0, 1, 4, bytes.len() / 2, bytes.len() - 1];
        for (case, cut) in cuts.into_iter().enumerate() {
            let archive = temporary.path().join(format!("truncated-{case}.{format}"));
            let staging = temporary.path().join(format!("staging-{format}-{case}"));
            fs::write(&archive, &bytes[..cut]).unwrap();

            assert!(
                extract_archive_to_staging(&archive, &staging, &ArchiveLimits::default()).is_err(),
                "{format} truncated to {cut} bytes was accepted"
            );
            assert!(!staging.exists());
        }
    }
}

#[test]
fn forged_zip_size_is_rejected_from_metadata() {
    let temporary = TempDir::new().unwrap();
    let archive = temporary.path().join("forged-size.zip");
    write_zip(&archive, b"pak", CompressionMethod::Stored);
    let mut bytes = fs::read(&archive).unwrap();
    let central_directory = bytes
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .unwrap();
    bytes[central_directory + 24..central_directory + 28].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&archive, bytes).unwrap();
    let limits = ArchiveLimits {
        max_file_bytes: 1024,
        max_expanded_bytes: 1024,
        ..ArchiveLimits::default()
    };

    let report = preflight_zip(&archive, &limits).unwrap();

    assert!(!report.accepted);
    assert!(
        report
            .rejections
            .iter()
            .any(|rejection| rejection.code == "file_too_large")
    );
    assert!(
        report
            .rejections
            .iter()
            .any(|rejection| rejection.code == "expanded_size_exceeded")
    );
}

#[test]
fn highly_compressed_zip_and_seven_zip_are_rejected_as_bombs() {
    let temporary = TempDir::new().unwrap();
    let contents = vec![0_u8; 1024 * 1024];
    let zip_archive = temporary.path().join("compression-bomb.zip");
    let seven_zip_source = temporary.path().join("compression-bomb.pak");
    let seven_zip_archive = temporary.path().join("compression-bomb.7z");
    write_zip(&zip_archive, &contents, CompressionMethod::Deflated);
    fs::write(&seven_zip_source, &contents).unwrap();
    sevenz_rust2::compress_to_path(&seven_zip_source, &seven_zip_archive).unwrap();
    let limits = ArchiveLimits {
        max_compression_ratio: 10,
        ..ArchiveLimits::default()
    };

    for archive in [zip_archive, seven_zip_archive] {
        let report = preflight_archive(&archive, &limits).unwrap();
        assert!(!report.accepted, "{} was accepted", archive.display());
        assert!(
            report
                .rejections
                .iter()
                .any(|rejection| rejection.code == "compression_ratio_exceeded"),
            "{} did not report its compression ratio",
            archive.display()
        );
    }
}

fn write_zip(path: &Path, contents: &[u8], compression: CompressionMethod) {
    let file = File::create(path).unwrap();
    let mut writer = zip::ZipWriter::new(file);
    writer
        .start_file(
            "Example_P.pak",
            SimpleFileOptions::default().compression_method(compression),
        )
        .unwrap();
    writer.write_all(contents).unwrap();
    writer.finish().unwrap();
}

fn write_seven_zip(path: &Path, method: sevenz_rust2::EncoderMethod) {
    let mut writer = sevenz_rust2::ArchiveWriter::create(path).unwrap();
    writer.set_encrypt_header(false);
    writer.set_content_methods(vec![method.into()]);
    writer
        .push_archive_entry(
            sevenz_rust2::ArchiveEntry::new_file("Example_P.pak"),
            Some(Cursor::new(b"pak fixture")),
        )
        .unwrap();
    writer.finish().unwrap();
}

fn replace_plain_header_lzma2_with_unknown_method(path: &Path) {
    const SIGNATURE_HEADER_BYTES: usize = 32;
    let original = fs::read(path).unwrap();
    let next_header_offset = u64::from_le_bytes(original[12..20].try_into().unwrap()) as usize;
    let next_header_size = u64::from_le_bytes(original[20..28].try_into().unwrap()) as usize;
    let start = SIGNATURE_HEADER_BYTES + next_header_offset;
    let end = start + next_header_size;
    let candidates: Vec<_> = original[start..end]
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == sevenz_rust2::EncoderMethod::ID_LZMA2[0])
        .map(|(offset, _)| start + offset)
        .collect();

    for method in candidates {
        let mut bytes = original.clone();
        bytes[method] = 0x7f;
        let next_header_crc = crc32(&bytes[start..end]);
        bytes[28..32].copy_from_slice(&next_header_crc.to_le_bytes());
        let start_header_crc = crc32(&bytes[12..32]);
        bytes[8..12].copy_from_slice(&start_header_crc.to_le_bytes());
        fs::write(path, bytes).unwrap();
        if sevenz_rust2::Archive::open(path).is_ok_and(|archive| {
            archive.blocks.iter().any(|block| {
                block
                    .coders
                    .iter()
                    .any(|coder| coder.encoder_method_id() == [0x7f])
            })
        }) {
            return;
        }
    }
    panic!("generated archive did not expose a mutable LZMA2 method ID");
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}
