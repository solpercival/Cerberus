use error::CaptureError;
use pcap::{Capture, Device};
use std::{thread, time::Duration};
use log::{info, warn, error};
use dotenvy::dotenv;
use std::env;

mod error;

fn main() -> Result<(), CaptureError> {
    // Load the .env file into the code environment
    dotenv().expect(".env file not found");

    let network_interface = env::var("NETWORK_INTERFACE").expect("NETWORK_INTERFACE not set");
    env_logger::init();
    start_capture(network_interface);

    Ok(())
}

pub fn start_capture(interface_name: &str) -> Result<(), CaptureError> { 
    info!("Starting packet capture on interface: '{}'", interface_name);

    let iface = Device::list()
        .map_err(CaptureError::DeviceListError)
        .into_iter()
        .find(|d| d.name == interface_name)
        .ok_or_else(|| CaptureError::InterfaceNotFound(interface_name.to_string()))?;
    
    info!("Interface found: {}", iface.name);

    let mut cap = Capture::from_device(iface)?
        .promisc(true)
        .immediate_mode(true)
        .open()?
        .setnonblock()?;

    let mut count = 0;
    let mut last_stats = None;

    loop {
        match cap.stats() {
            Ok(stats) => {
                let current = (stats.received, stats.dropped, stats.if_dropped);
                if last_stats != Some(current) {
                    last_stats = Some(current);
                    let (received, dropped, if_dropped) = current;
                    info!("Stats => received: {}, dropped: {}, kernel drop: {}", received, dropped, if_dropped);
                    info!("Delta recv - proccessed: {}", received.saturating_sub(count));
                }
            }
            Err(e) => warn!("Unable to retrieve stats: {:?}", e),
        }
    }
}