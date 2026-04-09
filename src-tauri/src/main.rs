// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Desktop binary entry point. The bulk of the application — Tauri
// Builder, command registration, state management — lives in
// `lib.rs` so it can be shared with the Android `cdylib` target.
// This file only handles desktop-specific concerns:
//   * filesystem logging to the user's Desktop
//   * the headless `bmsecresearch <pcap-file> [out.bin]` CLI mode
//   * delegating to `bmsecresearch_lib::run()` for the GUI

use std::path::{Path, PathBuf};

/// Filename of the single rolling app log dropped on the user's desktop.
/// Truncated on every app start so the desktop never accumulates more
/// than one log file from this app.
const DESKTOP_LOG_FILENAME: &str = "BMSecResearch.log";

/// Resolve the user's desktop directory cross-platform without pulling in
/// the `dirs` crate. Falls back to the home directory, then the current
/// directory, so we always have *somewhere* to write.
fn desktop_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(p) = std::env::var("USERPROFILE") {
            let candidate = PathBuf::from(p).join("Desktop");
            if candidate.exists() {
                return candidate;
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let candidate = PathBuf::from(&home).join("Desktop");
        if candidate.exists() {
            return candidate;
        }
        return PathBuf::from(home);
    }
    PathBuf::from(".")
}

/// Initialise logging. Writes to a single file on the user's desktop,
/// truncated on every start so we never accumulate stale log files. If
/// the file can't be created (permissions, read-only desktop, etc.) we
/// fall back to stderr so the user still sees something useful.
fn init_logging() {
    let log_path = desktop_dir().join(DESKTOP_LOG_FILENAME);
    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&log_path)
    {
        Ok(file) => {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                .format_timestamp_millis()
                .target(env_logger::Target::Pipe(Box::new(file)))
                .init();
            log::info!("BMSecResearch — log file: {}", log_path.display());
        }
        Err(e) => {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                .format_timestamp_millis()
                .init();
            log::warn!(
                "Could not open desktop log file {}: {} — logging to stderr instead",
                log_path.display(),
                e
            );
        }
    }
}

/// Install a panic hook that appends panic info + backtrace to a
/// dedicated crash file next to the log. We write directly with
/// `std::fs` so we don't depend on env_logger's buffered pipe (which
/// can lose the final lines when the process is aborting).
fn install_panic_hook() {
    let crash_path = desktop_dir().join("BMSecResearch.crash.log");
    std::env::set_var("RUST_BACKTRACE", "1");
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = format!(
            "\n=== PANIC @ {:?} ===\n{}\nBacktrace:\n{}\n",
            std::time::SystemTime::now(),
            info,
            std::backtrace::Backtrace::force_capture()
        );
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&crash_path)
        {
            use std::io::Write;
            let _ = f.write_all(msg.as_bytes());
            let _ = f.flush();
        }
        log::error!("{}", msg);
        default_hook(info);
    }));
}

fn main() {
    init_logging();
    install_panic_hook();

    // CLI mode: pass a .pcap path as argument for headless extraction.
    // Mobile targets don't have CLI mode (no argv on Android).
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1].ends_with(".pcap") {
        cli_extract(&args[1], args.get(2).map(|s| s.as_str()));
        return;
    }

    bmsecresearch_lib::run();
}

/// CLI extraction mode for testing and automation. Desktop-only — uses
/// the re-exported pipeline modules from the library crate.
fn cli_extract(pcap_path: &str, output_path: Option<&str>) {
    use bmsecresearch_lib::{assembler, hsfz_parser, pcap_reader, tcp_reassembly, uds_session};

    println!("=== BMSecResearch — PCAP Extractor (CLI) ===\n");

    let path = Path::new(pcap_path);
    println!("[1/4] Reading PCAP: {}", pcap_path);

    let packets = match pcap_reader::read_pcap(path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error reading PCAP: {}", e);
            std::process::exit(1);
        }
    };
    println!("  {} TCP packets on port 6801", packets.len());

    println!("[2/4] Reassembling TCP streams...");
    let streams = tcp_reassembly::reassemble_streams(packets);
    for stream in &streams {
        println!(
            "  {} ({} bytes, {} packets)",
            stream.direction_label(),
            stream.data.len(),
            stream.packet_count,
        );
    }

    println!("[3/4] Parsing HSFZ/UDS frames...");
    let mut all_frames = Vec::new();
    for stream in &streams {
        if stream.data.len() < 10_000 {
            continue;
        }
        let frames = hsfz_parser::parse_hsfz_frames(&stream.data);
        println!(
            "  {}: {} HSFZ frames",
            stream.direction_label(),
            frames.len()
        );
        all_frames.extend(frames);
    }

    let session_result = uds_session::extract_sessions(&all_frames);

    if session_result.block_data.is_empty() {
        eprintln!("\nNo flash sessions found!");
        std::process::exit(1);
    }

    for evt in &session_result.events {
        println!("  {} {}", evt.event_type, evt.detail);
    }

    println!("\n[4/4] Assembling binary...");
    let result = match assembler::assemble_binary(
        &session_result.segments,
        &session_result.block_data,
        session_result.events,
        session_result.vin,
        session_result.ecu_address,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error assembling binary: {}", e);
            std::process::exit(1);
        }
    };

    println!("  VIN: {}", result.vin.as_deref().unwrap_or("N/A"));
    println!("  ECU: 0x{:02X}", result.ecu_address);
    println!("  Base: 0x{:08X}", result.base_address);
    println!(
        "  Size: {} bytes ({:.2} MB)",
        result.binary_size,
        result.binary_size as f64 / 1024.0 / 1024.0
    );
    println!("  Content: {:.1}% non-0xFF", result.non_ff_percent);

    for seg in &result.segments {
        let status = if seg.size_match { "OK" } else { "MISMATCH" };
        println!(
            "  0x{:08X}: {} bytes ({} blocks) [{}]",
            seg.address, seg.actual_size, seg.block_count, status
        );
    }

    let out = output_path.unwrap_or("extracted_flash.bin");
    let out_path = Path::new(out);
    match assembler::save_binary(&session_result.block_data, result.base_address, out_path) {
        Ok(size) => println!("\n  Saved {} bytes to {}", size, out),
        Err(e) => eprintln!("\n  Save error: {}", e),
    }

    println!("\n=== Done ===");
}
