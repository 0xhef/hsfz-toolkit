//! Cross-platform app data path resolution.
//!
//! On desktop, the data root resolves to a per-user XDG data location
//! (`%LOCALAPPDATA%\bmsecresearch\` on Windows, `~/.local/share/bmsecresearch/`
//! on Linux/macOS via XDG fallbacks). On Android, it resolves via Tauri's
//! `app.path().app_data_dir()` to the app-scoped *external* storage area
//! (`/storage/emulated/0/Android/data/org.bmsecresearch.app/files/`),
//! which is writable by the app without permissions AND visible to file
//! managers without root — the app-private internal storage that the
//! XDG fallback would otherwise pick (`/data/user/0/<package>/files/`)
//! is invisible to users on a stock Android device.
//!
//! The data root is computed once during the Tauri Builder's `setup`
//! callback and stored in a process-wide `OnceLock` so any code path
//! (Tauri commands, the simulator capture engine, profile loaders,
//! etc.) can read it without threading `AppHandle` through every
//! function. The `OnceLock` is set exactly once at startup and read
//! many times thereafter — no synchronisation overhead after init.
//!
//! On any platform, if the OnceLock hasn't been initialised yet (e.g.
//! during unit tests that don't go through Tauri's setup callback) we
//! fall back to the legacy XDG/LOCALAPPDATA path so existing test
//! fixtures keep working.

use std::path::PathBuf;
use std::sync::OnceLock;

/// Process-wide app data root, set once at Tauri startup.
static APP_DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Initialise the app data root. Called from `lib::run`'s Tauri Builder
/// `setup` callback with the result of `app.path().app_data_dir()`.
/// Subsequent calls are no-ops (OnceLock can only be set once).
pub fn init(path: PathBuf) {
    if APP_DATA_DIR.set(path.clone()).is_err() {
        log::warn!(
            "app_paths::init called twice — keeping the first value, ignoring {}",
            path.display()
        );
    } else {
        log::info!("app_paths: data root = {}", path.display());
    }
    // Best-effort directory creation so the first read/list call
    // doesn't fail with "No such file or directory".
    if let Some(p) = APP_DATA_DIR.get() {
        let _ = std::fs::create_dir_all(p);
    }
}

/// Returns the app data root, falling back to a desktop-style
/// XDG/LOCALAPPDATA location if init hasn't been called (typical case:
/// running unit tests outside the Tauri runtime).
pub fn data_dir() -> PathBuf {
    APP_DATA_DIR
        .get()
        .cloned()
        .unwrap_or_else(fallback_data_dir)
}

/// Cross-platform XDG-style fallback. Mirrors the legacy path resolution
/// that lived in `simulator/profile.rs` and `simulator/capture.rs` before
/// the Android storage refactor — kept for environments that haven't
/// gone through Tauri's setup callback (unit tests, CLI mode).
fn fallback_data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(p).join("bmsecresearch");
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(p) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(p).join("bmsecresearch");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("bmsecresearch");
    }
    PathBuf::from(".").join("bmsecresearch")
}

/// Convenience: the simulator profiles directory.
pub fn profiles_dir() -> PathBuf {
    let dir = data_dir().join("profiles");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Convenience: the simulator + proxy captures root directory.
pub fn captures_dir() -> PathBuf {
    let dir = data_dir().join("captures");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Convenience: the proxy session captures directory.
pub fn proxy_captures_dir() -> PathBuf {
    let dir = data_dir().join("proxy_captures");
    let _ = std::fs::create_dir_all(&dir);
    dir
}
