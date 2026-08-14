use anyhow::{Result, ensure};
use rrmm_application::{DesktopApplication, DesktopPaths};
use std::path::PathBuf;

fn main() -> Result<()> {
    let app = DesktopApplication::new(
        DesktopPaths::for_local_user()?,
        PathBuf::from("target/release/rrmm-archive-worker"),
        PathBuf::from("target/release/rrmm-pak-worker"),
    )?;
    let preview = app.preview_activation(false)?;
    println!("{}", serde_json::to_string_pretty(&preview)?);
    ensure!(!preview.blocked, "activation preview is blocked");
    println!(
        "{}",
        serde_json::to_string_pretty(&app.apply_activation(&preview.preview_id)?)?
    );
    Ok(())
}
