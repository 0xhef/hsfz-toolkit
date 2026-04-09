// `parser` and `state` are pure Rust with no platform deps and compile
// everywhere. They're shared between the offline pcap-file reader and
// the live capture engine.
pub mod parser;
pub mod state;

// `engine` uses the libpcap Rust binding directly and is gated behind
// the `libpcap` Cargo feature. On builds without that feature (e.g.
// the default Android sideload bundle), live capture is unavailable
// and the operator uses the Proxy tab for capture instead.
#[cfg(feature = "libpcap")]
pub mod engine;

// `interfaces` defines the `NetworkInterface` struct unconditionally
// (so the Tauri command surface stays the same on every build) but
// only implements the libpcap-backed `list_interfaces` body when the
// feature is enabled.
pub mod interfaces;
