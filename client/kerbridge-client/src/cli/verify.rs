//! `--verify`: prove end to end that the platform's own SMB client uses the
//! ticket just injected.

use anyhow::{Context, Result};

/// Demonstrate that the platform's own SMB client uses the injected ticket.
///
/// `share` is a UNC path on Windows and the mount point of an already-mounted
/// share on macOS, which is why the two names below are joined rather than
/// formatted: the separator is the platform's.
pub(crate) fn verify_share(share: &str, principal: &str) -> Result<()> {
    println!("[kerbridge] accessing {share} as {principal} through the stock SMB client:");

    // Tickets currently held (the cifs/nas TGS appears after first access).
    run_klist();

    let readme = std::path::Path::new(share).join("README.txt");
    match std::fs::read_to_string(&readme) {
        Ok(content) => println!("--- {} ---\n{}", readme.display(), content.trim_end()),
        Err(e) => println!("[kerbridge] could not read {}: {e}", readme.display()),
    }

    // Fixed filename: the principal is not secret, but keeping it out of the
    // path avoids putting realm-derived text into a filesystem name.
    let stamp_path = std::path::Path::new(share).join("kerbridge-was-here.txt");
    let stamp = format!("{principal} reached this share via cloud identity, no password\n");
    std::fs::write(&stamp_path, stamp)
        .with_context(|| format!("writing {}", stamp_path.display()))?;
    println!("[kerbridge] wrote {}", stamp_path.display());

    // Now the cifs/<nas> service ticket should be cached.
    run_klist();
    Ok(())
}

fn run_klist() {
    println!("[kerbridge] --- klist ---");
    let _ = std::process::Command::new("klist").status();
}
