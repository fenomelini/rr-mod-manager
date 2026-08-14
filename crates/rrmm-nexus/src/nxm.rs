use crate::GAME_DOMAIN;
use std::fmt;
use std::num::NonZeroU64;
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_NXM_BYTES: usize = 4_096;
const MIN_KEY_BYTES: usize = 8;
const MAX_KEY_BYTES: usize = 512;

pub struct NxmRequest {
    pub mod_id: NonZeroU64,
    pub nxm_file_id: NonZeroU64,
    pub user_id: Option<NonZeroU64>,
    authorization: Option<NxmAuthorization>,
}

struct NxmAuthorization {
    _key: Zeroizing<String>,
    expires: u64,
}

impl NxmRequest {
    pub fn has_authorization(&self) -> bool {
        self.authorization.is_some()
    }

    pub fn authorization_is_expired_at(&self, unix_seconds: u64) -> Option<bool> {
        self.authorization
            .as_ref()
            .map(|authorization| authorization.expires <= unix_seconds)
    }

    pub fn safe_summary(&self) -> String {
        format!(
            "Nexus request for mod {} file {} (temporary authorization: {})",
            self.mod_id,
            self.nxm_file_id,
            if self.has_authorization() {
                "present"
            } else {
                "absent"
            }
        )
    }
}

impl fmt::Debug for NxmRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NxmRequest")
            .field("mod_id", &self.mod_id)
            .field("nxm_file_id", &self.nxm_file_id)
            .field("user_id", &self.user_id)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NxmParseError {
    #[error("Nexus link exceeds the size limit")]
    TooLong,
    #[error("Nexus link contains forbidden characters")]
    ForbiddenCharacters,
    #[error("Nexus link scheme is invalid")]
    InvalidScheme,
    #[error("Nexus link target is invalid")]
    InvalidTarget,
    #[error("Nexus link path is invalid")]
    InvalidPath,
    #[error("Nexus link identifier is invalid")]
    InvalidIdentifier,
    #[error("Nexus link query is invalid")]
    InvalidQuery,
    #[error("Nexus temporary authorization is invalid")]
    InvalidAuthorization,
}

pub fn parse_nxm_url(input: &str) -> Result<NxmRequest, NxmParseError> {
    if input.len() > MAX_NXM_BYTES {
        return Err(NxmParseError::TooLong);
    }
    if input.is_empty()
        || input
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(NxmParseError::ForbiddenCharacters);
    }
    let (scheme, remainder) = input
        .split_once("://")
        .ok_or(NxmParseError::InvalidScheme)?;
    if scheme != "nxm" {
        return Err(NxmParseError::InvalidScheme);
    }
    if remainder.contains('#') || remainder.matches('?').count() > 1 {
        return Err(NxmParseError::InvalidTarget);
    }
    let (authority_and_path, query) = remainder
        .split_once('?')
        .map_or((remainder, None), |(path, query)| (path, Some(query)));
    let (authority, path) = authority_and_path
        .split_once('/')
        .ok_or(NxmParseError::InvalidTarget)?;
    if authority != GAME_DOMAIN || authority.contains(['@', ':', '\\', '%']) {
        return Err(NxmParseError::InvalidTarget);
    }
    if path.contains(['%', '\\']) {
        return Err(NxmParseError::InvalidPath);
    }
    let path = path.strip_suffix('/').unwrap_or(path);
    let segments: Vec<_> = path.split('/').collect();
    if segments.len() != 4 || segments[0] != "mods" || segments[2] != "files" {
        return Err(NxmParseError::InvalidPath);
    }
    let mod_id = parse_identifier(segments[1])?;
    let nxm_file_id = parse_identifier(segments[3])?;

    let mut key = None;
    let mut expires = None;
    let mut user_id = None;
    if let Some(query) = query {
        if query.is_empty() {
            return Err(NxmParseError::InvalidQuery);
        }
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').ok_or(NxmParseError::InvalidQuery)?;
            if name.is_empty() || value.is_empty() || value.contains(';') {
                return Err(NxmParseError::InvalidQuery);
            }
            match name {
                "key" if key.is_none() => key = Some(percent_decode(value)?),
                "expires" if expires.is_none() => {
                    let value = parse_u64(value)?;
                    if value == 0 {
                        return Err(NxmParseError::InvalidAuthorization);
                    }
                    expires = Some(value);
                }
                "user_id" if user_id.is_none() => user_id = Some(parse_identifier(value)?),
                _ => return Err(NxmParseError::InvalidQuery),
            }
        }
    }
    let authorization = match (key, expires) {
        (Some(key), Some(expires))
            if (MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&key.len())
                && !key
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()) =>
        {
            Some(NxmAuthorization {
                _key: Zeroizing::new(key),
                expires,
            })
        }
        (None, None) => None,
        _ => return Err(NxmParseError::InvalidAuthorization),
    };
    Ok(NxmRequest {
        mod_id,
        nxm_file_id,
        user_id,
        authorization,
    })
}

fn parse_identifier(value: &str) -> Result<NonZeroU64, NxmParseError> {
    if value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(NxmParseError::InvalidIdentifier);
    }
    NonZeroU64::new(parse_u64(value)?).ok_or(NxmParseError::InvalidIdentifier)
}

fn parse_u64(value: &str) -> Result<u64, NxmParseError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(NxmParseError::InvalidIdentifier);
    }
    value.parse().map_err(|_| NxmParseError::InvalidIdentifier)
}

fn percent_decode(value: &str) -> Result<String, NxmParseError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1).ok_or(NxmParseError::InvalidQuery)?;
            let low = *bytes.get(index + 2).ok_or(NxmParseError::InvalidQuery)?;
            decoded.push(
                hex_value(high)
                    .and_then(|high| hex_value(low).map(|low| high * 16 + low))
                    .ok_or(NxmParseError::InvalidQuery)?,
            );
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| NxmParseError::InvalidQuery)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_links_without_exposing_authorization() {
        let secret = "synthetic-secret-key";
        let input =
            format!("nxm://{GAME_DOMAIN}/mods/12/files/34?key={secret}&expires=200&user_id=56");
        let parsed = parse_nxm_url(&input).unwrap();

        assert_eq!(parsed.mod_id.get(), 12);
        assert_eq!(parsed.nxm_file_id.get(), 34);
        assert_eq!(parsed.user_id.unwrap().get(), 56);
        assert!(parsed.has_authorization());
        assert_eq!(parsed.authorization_is_expired_at(199), Some(false));
        assert_eq!(parsed.authorization_is_expired_at(200), Some(true));
        assert!(!format!("{parsed:?}").contains(secret));
        assert!(!parsed.safe_summary().contains(secret));
        assert!(!parsed.safe_summary().contains("200"));
    }

    #[test]
    fn accepts_an_optional_trailing_slash_and_no_authorization() {
        let parsed = parse_nxm_url(&format!("nxm://{GAME_DOMAIN}/mods/1/files/2/")).unwrap();
        assert!(!parsed.has_authorization());
        assert_eq!(parsed.authorization_is_expired_at(0), None);
    }

    #[test]
    fn rejects_target_path_and_identifier_confusion() {
        for input in [
            "https://retrorewindvideostoresimulator/mods/1/files/2",
            "nxm://evilretrorewindvideostoresimulator/mods/1/files/2",
            "nxm://retrorewindvideostoresimulator:443/mods/1/files/2",
            "nxm://user@retrorewindvideostoresimulator/mods/1/files/2",
            "nxm://retrorewindvideostoresimulator/mods/1/files/2#fragment",
            "nxm://retrorewindvideostoresimulator/mods/1/files%2f2",
            "nxm://retrorewindvideostoresimulator/mods/01/files/2",
            "nxm://retrorewindvideostoresimulator/mods/1/files/0",
            "nxm://retrorewindvideostoresimulator/mods/1/files/18446744073709551616",
        ] {
            assert!(parse_nxm_url(input).is_err(), "accepted {input}");
        }
    }

    #[test]
    fn rejects_ambiguous_or_partial_queries() {
        for query in [
            "key=abcdefgh",
            "expires=123",
            "key=abcdefgh&expires=123&key=ijklmnop",
            "%6bey=abcdefgh&expires=123",
            "key=abcdefgh&expires=123&unknown=1",
            "key=bad%ZZvalue&expires=123",
            "key=short&expires=123",
            "user_id=0",
        ] {
            let input = format!("nxm://{GAME_DOMAIN}/mods/1/files/2?{query}");
            assert!(parse_nxm_url(&input).is_err(), "accepted {input}");
        }
    }
}
