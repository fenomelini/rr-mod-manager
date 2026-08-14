mod nxm;
mod v3;

pub use nxm::{NxmParseError, NxmRequest, parse_nxm_url};
pub use v3::{ApiResponse, NexusError, NexusV3Client, RateLimitSnapshot, TrendingMod};

pub const GAME_DOMAIN: &str = "retrorewindvideostoresimulator";
pub const NEXUS_V3_BASE: &str = "https://api.nexusmods.com/v3";
