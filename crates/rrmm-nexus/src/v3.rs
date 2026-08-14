use crate::{GAME_DOMAIN, NEXUS_V3_BASE};
use reqwest::blocking::{Client, Response};
use reqwest::header::{CONTENT_TYPE, HeaderMap, RETRY_AFTER};
use serde::Deserialize;
use std::io::Read;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use thiserror::Error;

const MAX_RESPONSE_BYTES: usize = 1_048_576;
const DEFAULT_COOLDOWN_SECONDS: u64 = 60;

pub struct NexusV3Client {
    client: Client,
    base: String,
    cooldown_until: Mutex<Option<Instant>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrendingMod {
    pub mod_id: u64,
    pub name: String,
    pub author: Option<String>,
    pub summary: Option<String>,
    pub page_url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateLimitSnapshot {
    pub hourly_limit: Option<u64>,
    pub hourly_remaining: Option<u64>,
    pub daily_limit: Option<u64>,
    pub daily_remaining: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiResponse<T> {
    pub data: T,
    pub rate_limit: RateLimitSnapshot,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NexusError {
    #[error("Nexus request failed")]
    Transport,
    #[error("Nexus returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("Nexus rate limit is active; retry after {retry_after_seconds} seconds")]
    RateLimited { retry_after_seconds: u64 },
    #[error("Nexus response exceeded the size limit")]
    ResponseTooLarge,
    #[error("Nexus response was not valid for the requested operation")]
    InvalidResponse,
    #[error("Nexus client configuration is invalid")]
    InvalidConfiguration,
}

impl NexusV3Client {
    pub fn production() -> Result<Self, NexusError> {
        Self::new(NEXUS_V3_BASE)
    }

    fn new(base: &str) -> Result<Self, NexusError> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| NexusError::InvalidConfiguration)?;
        Ok(Self {
            client,
            base: base.trim_end_matches('/').to_owned(),
            cooldown_until: Mutex::new(None),
        })
    }

    pub fn get_public_trending_mods(&self) -> Result<ApiResponse<Vec<TrendingMod>>, NexusError> {
        self.enforce_cooldown()?;
        let response = self
            .client
            .get(format!("{}/games/{GAME_DOMAIN}/trending-mods", self.base))
            .header("Application-Name", "RR Mod Manager")
            .header("Application-Version", env!("CARGO_PKG_VERSION"))
            .header(
                reqwest::header::USER_AGENT,
                format!(
                    "RRModManager/{} ({}; {})",
                    env!("CARGO_PKG_VERSION"),
                    std::env::consts::OS,
                    std::env::consts::ARCH
                ),
            )
            .send()
            .map_err(|_| NexusError::Transport)?;
        let rate_limit = rate_limit_snapshot(response.headers());
        if response.status().as_u16() == 429 {
            let retry_after_seconds = response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(DEFAULT_COOLDOWN_SECONDS)
                .max(1);
            *self
                .cooldown_until
                .lock()
                .map_err(|_| NexusError::Transport)? =
                Some(Instant::now() + Duration::from_secs(retry_after_seconds));
            return Err(NexusError::RateLimited {
                retry_after_seconds,
            });
        }
        if !response.status().is_success() {
            return Err(NexusError::HttpStatus(response.status().as_u16()));
        }
        require_json(response.headers())?;
        let body = bounded_body(response)?;
        let wire: TrendingEnvelope =
            serde_json::from_slice(&body).map_err(|_| NexusError::InvalidResponse)?;
        if wire.data.mods.len() > 5 {
            return Err(NexusError::InvalidResponse);
        }
        let data = wire
            .data
            .mods
            .into_iter()
            .map(validate_trending_mod)
            .collect::<Result<_, _>>()?;
        Ok(ApiResponse { data, rate_limit })
    }

    fn enforce_cooldown(&self) -> Result<(), NexusError> {
        let mut cooldown = self
            .cooldown_until
            .lock()
            .map_err(|_| NexusError::Transport)?;
        if let Some(until) = *cooldown {
            if let Some(remaining) = until.checked_duration_since(Instant::now()) {
                return Err(NexusError::RateLimited {
                    retry_after_seconds: remaining.as_secs().max(1),
                });
            }
            *cooldown = None;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct TrendingEnvelope {
    data: TrendingData,
}

#[derive(Deserialize)]
struct TrendingData {
    mods: Vec<TrendingWire>,
}

#[derive(Deserialize)]
struct TrendingWire {
    name: String,
    mod_page_url: String,
    author: Option<String>,
    summary: Option<String>,
}

fn validate_trending_mod(wire: TrendingWire) -> Result<TrendingMod, NexusError> {
    if wire.name.is_empty()
        || wire.name.len() > 512
        || wire.author.as_ref().is_some_and(|value| value.len() > 512)
        || wire
            .summary
            .as_ref()
            .is_some_and(|value| value.len() > 4_096)
    {
        return Err(NexusError::InvalidResponse);
    }
    let url = reqwest::Url::parse(&wire.mod_page_url).map_err(|_| NexusError::InvalidResponse)?;
    if url.scheme() != "https"
        || url.host_str() != Some("www.nexusmods.com")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(NexusError::InvalidResponse);
    }
    let segments: Vec<_> = url
        .path_segments()
        .ok_or(NexusError::InvalidResponse)?
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.len() != 3 || segments[0] != GAME_DOMAIN || segments[1] != "mods" {
        return Err(NexusError::InvalidResponse);
    }
    let mod_id = segments[2]
        .parse::<u64>()
        .ok()
        .filter(|id| *id > 0 && !segments[2].starts_with('0'))
        .ok_or(NexusError::InvalidResponse)?;
    Ok(TrendingMod {
        mod_id,
        name: wire.name,
        author: wire.author,
        summary: wire.summary,
        page_url: wire.mod_page_url,
    })
}

fn require_json(headers: &HeaderMap) -> Result<(), NexusError> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if content_type
        .split(';')
        .next()
        .is_none_or(|value| value.trim() != "application/json")
    {
        return Err(NexusError::InvalidResponse);
    }
    Ok(())
}

fn bounded_body(response: Response) -> Result<Vec<u8>, NexusError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(NexusError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    response
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|_| NexusError::Transport)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(NexusError::ResponseTooLarge);
    }
    Ok(body)
}

fn rate_limit_snapshot(headers: &HeaderMap) -> RateLimitSnapshot {
    RateLimitSnapshot {
        hourly_limit: numeric_header(headers, "x-rl-hourly-limit"),
        hourly_remaining: numeric_header(headers, "x-rl-hourly-remaining"),
        daily_limit: numeric_header(headers, "x-rl-daily-limit"),
        daily_remaining: numeric_header(headers, "x-rl-daily-remaining"),
    }
}

fn numeric_header(headers: &HeaderMap, name: &str) -> Option<u64> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    fn serve_once(
        status: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let response_headers = headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .collect::<String>();
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{response_headers}Connection: close\r\n\r\n{body}",
            body.len()
        );
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 8_192];
            let length = stream.read(&mut request).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&request[..length]).into_owned()
        });
        (format!("http://{address}"), handle)
    }

    #[test]
    fn fetches_the_fixed_public_feed_with_truthful_headers() {
        let body = format!(
            r#"{{"data":{{"mods":[{{"name":"Example","author":null,"summary":"Safe","mod_page_url":"https://www.nexusmods.com/{GAME_DOMAIN}/mods/12","new_field":true}}]}}}}"#
        );
        let (base, request) = serve_once(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("x-rl-hourly-remaining", "499"),
            ],
            &body,
        );
        let client = NexusV3Client::new(&base).unwrap();

        let response = client.get_public_trending_mods().unwrap();

        assert_eq!(response.data[0].mod_id, 12);
        assert_eq!(response.rate_limit.hourly_remaining, Some(499));
        let request = request.join().unwrap();
        assert!(request.starts_with(&format!("GET /games/{GAME_DOMAIN}/trending-mods HTTP/1.1")));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("application-name: rr mod manager")
        );
        assert!(request.to_ascii_lowercase().contains(&format!(
            "application-version: {}",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(!request.to_ascii_lowercase().contains("authorization:"));
        assert!(!request.to_ascii_lowercase().contains("apikey:"));
    }

    #[test]
    fn rejects_unreviewed_page_urls_and_schema_expansion() {
        let body =
            r#"{"data":{"mods":[{"name":"Bad","mod_page_url":"https://evil.example/mods/1"}]}}"#;
        let (base, request) = serve_once("200 OK", &[("Content-Type", "application/json")], body);
        let client = NexusV3Client::new(&base).unwrap();
        assert!(matches!(
            client.get_public_trending_mods(),
            Err(NexusError::InvalidResponse)
        ));
        request.join().unwrap();
    }

    #[test]
    fn rate_limit_sets_a_local_cooldown_without_retrying() {
        let (base, request) = serve_once("429 Too Many Requests", &[("Retry-After", "30")], "{}");
        let client = NexusV3Client::new(&base).unwrap();

        assert!(matches!(
            client.get_public_trending_mods(),
            Err(NexusError::RateLimited {
                retry_after_seconds: 30
            })
        ));
        request.join().unwrap();
        assert!(matches!(
            client.get_public_trending_mods(),
            Err(NexusError::RateLimited { .. })
        ));
    }

    #[test]
    fn rejects_non_json_success_without_exposing_the_body() {
        let (base, request) = serve_once("200 OK", &[("Content-Type", "text/html")], "secret body");
        let client = NexusV3Client::new(&base).unwrap();
        let error = client.get_public_trending_mods().unwrap_err();
        assert!(matches!(error, NexusError::InvalidResponse));
        assert!(!error.to_string().contains("secret body"));
        request.join().unwrap();
    }
}
