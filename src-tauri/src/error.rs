use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum PcapError {
    #[error("Not a valid PCAP file (bad magic: {0:#010x})")]
    InvalidMagic(u32),

    #[error("Unsupported link type: {0} (expected Ethernet=1)")]
    UnsupportedLinkType(u32),

    #[error("Truncated packet at offset {0}")]
    TruncatedPacket(u64),

    #[error("Packet exceeds maximum allowed size")]
    PacketTooLarge,

    #[error("Capture exceeds maximum allowed size")]
    CaptureTooLarge,

    #[error("No HSFZ streams found on port 6801")]
    NoHsfzStreams,

    #[error("No flash download sessions found in capture")]
    NoFlashSessions,

    /// Wraps a libpcap error message. Only constructed by the live
    /// capture engine and the libpcap-backed `list_interfaces`, both
    /// of which are gated behind the `libpcap` Cargo feature, so the
    /// variant follows the same gate.
    #[cfg(feature = "libpcap")]
    #[error("Packet capture library error: {0}")]
    PcapLibrary(String),

    /// Returned by `start_capture` when a capture session is already
    /// active. Only constructable when the `libpcap` feature is on,
    /// because that's the only path that ever populates `session`.
    #[cfg(feature = "libpcap")]
    #[error("Capture is already running")]
    CaptureAlreadyRunning,

    #[error("No active capture to stop")]
    NoCaptureRunning,

    #[error("Invalid file path")]
    InvalidPath,

    #[error("Internal state error")]
    StateLock,

    #[error("Unable to read file")]
    Io(#[from] std::io::Error),

    /// Returned when a feature-gated capability is invoked on a build
    /// that doesn't include it. Currently only constructed when the
    /// `libpcap` Cargo feature is disabled — the live capture commands
    /// return this from their stub implementations so the frontend gets
    /// a clear "not compiled in" message instead of a `command not
    /// found` IPC error. Gated on the same condition as the construction
    /// sites in `capture/interfaces.rs` and `commands.rs::start_capture`,
    /// so the variant only exists when it can actually be produced —
    /// builds with libpcap enabled don't carry a dead variant.
    #[cfg(not(feature = "libpcap"))]
    #[error("{0}")]
    PlatformUnsupported(String),
}

impl PcapError {
    /// Returns a user-facing message safe for display in the frontend.
    /// Internal details (OS error messages, paths) are logged but not exposed.
    fn user_message(&self) -> String {
        match self {
            Self::Io(e) => {
                log::error!("IO error: {}", e);
                "Unable to read file".to_string()
            }
            // The PcapLibrary arm hides the raw libpcap error string from
            // the user (it can leak host paths and library version info)
            // and replaces it with an actionable hint. Gated on the same
            // condition as the variant itself.
            #[cfg(feature = "libpcap")]
            Self::PcapLibrary(msg) => {
                log::error!("Pcap library error: {}", msg);
                "Packet capture unavailable (is Npcap/libpcap installed?)".to_string()
            }
            // All other variants have static messages that don't leak details
            other => other.to_string(),
        }
    }
}

impl Serialize for PcapError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.user_message())
    }
}
