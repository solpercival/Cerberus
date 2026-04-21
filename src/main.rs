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

    Ok(())
}

pub fn start_capture()