use thiserror:Error;
use pcap:Error as PcapError;

#[derive(Error, Debug)]
pub enum CaptureError {
    #[error("Network interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Error listing network interfaces: {0}")]
    DeviceListError(#[from]PcapError),

    #[error("Failed to initialize capture {0}")]
    CaptureInitError(#[from] PcapError),
}