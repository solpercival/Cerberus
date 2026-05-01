use error::CaptureError;
use pcap::{Capture, Device};
use std::{thread, time::{Duration, Instant}};
use log::{info, warn, error};
use dotenvy::dotenv;
use std::env;
use etherparse::{SlicedPacket, TransportSlice, LinkSlice, NetSlice};

mod error;

fn main() -> Result<(), CaptureError> {
    if std::env::args().any(|a| a == "--list") {
        return list_devices();
    }

    // Load the .env file into the code environment
    dotenv().expect(".env file not found");

    let network_interface = env::var("NETWORK_INTERFACE").expect("NETWORK_INTERFACE not set");
    env_logger::init();
    start_capture(&network_interface)?;

    Ok(())
}

fn list_devices() -> Result<(), CaptureError> {
    let devices = Device::list().map_err(CaptureError::DeviceListError)?;
    println!("{:<5} {:<50} {}", "No.", "Name", "Description");
    println!("{}", "-".repeat(90));
    for (i, d) in devices.iter().enumerate() {
        let desc = d.desc.as_deref().unwrap_or("(no description)");
        println!("{:<5} {:<50} {}", i + 1, d.name, desc);
    }
    Ok(())
}

pub fn start_capture(interface_name: &str) -> Result<(), CaptureError> { 
    info!("Starting packet capture on interface: '{}'", interface_name);

    let iface = Device::list()
        .map_err(CaptureError::DeviceListError)?
        .into_iter()
        .find(|d| d.name == interface_name)
        .ok_or_else(|| CaptureError::InterfaceNotFound(interface_name.to_string()))?;
    
    info!("Interface found: {}", iface.name);

    let mut cap = Capture::from_device(iface)
        .map_err(|e| CaptureError::DeviceListError(e))?
        .promisc(true)
        .immediate_mode(true)
        .open()
        .map_err(|e| CaptureError::DeviceListError(e))?
        .setnonblock()
        .map_err(|e| CaptureError::DeviceListError(e))?;

    let mut count = 0;
    let mut last_stats = None;
    let deadline = Instant::now() + Duration::from_secs(15);

    loop {
        if Instant::now() >= deadline {
            info!("15 second time limit reached, stopping capture.");
            break;
        }
        match cap.stats() {
            Ok(stats) => {
                let current = (stats.received, stats.dropped, stats.if_dropped);
                if last_stats != Some(current) {
                    last_stats = Some(current);
                    let (received, dropped, if_dropped) = current;
                    info!("Stats => received: {}, dropped: {}, kernel drop: {}", received, dropped, if_dropped);
                    info!("Delta recv - processed: {}", received.saturating_sub(count));
                }
            }
            Err(e) => warn!("Unable to retrieve stats: {:?}", e)
        }
        match cap.next_packet() {
            Ok(packet) => {
                count += 1;
                let ts = format!("{}.{:06}", packet.header.ts.tv_sec, packet.header.ts.tv_usec);
                match SlicedPacket::from_ethernet(packet.data) {
                    Ok(parsed) => {
                        // Ethernet
                        if let Some(LinkSlice::Ethernet2(eth)) = &parsed.link {
                            let src = eth.source();
                            let dst = eth.destination();
                            info!(
                                "[{}] #{} ETH {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                ts, count,
                                src[0], src[1], src[2], src[3], src[4], src[5],
                                dst[0], dst[1], dst[2], dst[3], dst[4], dst[5],
                            );
                        }
                        // IP
                        match &parsed.net {
                            Some(NetSlice::Ipv4(ipv4)) => {
                                let h = ipv4.header();
                                info!("  IPv4 {} -> {} ttl={}",
                                    std::net::Ipv4Addr::from(h.source()),
                                    std::net::Ipv4Addr::from(h.destination()),
                                    h.ttl());
                            }
                            Some(NetSlice::Ipv6(ipv6)) => {
                                let h = ipv6.header();
                                info!("  IPv6 {} -> {} hop={}",
                                    std::net::Ipv6Addr::from(h.source()),
                                    std::net::Ipv6Addr::from(h.destination()),
                                    h.hop_limit());
                            }
                            _ => {}
                        }
                        // Transport
                        match &parsed.transport {
                            Some(TransportSlice::Tcp(tcp)) => {
                                info!("  TCP port {} -> {} [{}{}{}{}]",
                                    tcp.source_port(), tcp.destination_port(),
                                    if tcp.syn() { "SYN " } else { "" },
                                    if tcp.ack() { "ACK " } else { "" },
                                    if tcp.fin() { "FIN " } else { "" },
                                    if tcp.rst() { "RST" } else { "" },
                                );
                            }
                            Some(TransportSlice::Udp(udp)) => {
                                info!("  UDP port {} -> {} len={}",
                                    udp.source_port(), udp.destination_port(), udp.length());
                            }
                            Some(TransportSlice::Icmpv4(icmp)) => {
                                info!("  ICMPv4 type={:?}", icmp.icmp_type());
                            }
                            Some(TransportSlice::Icmpv6(icmp)) => {
                                info!("  ICMPv6 type={:?}", icmp.icmp_type());
                            }
                            _ => {}
                        }
                    }
                    Err(_) => {
                        info!("[{}] #{} RAW len={}", ts, count, packet.data.len());
                    }
                }
            }
            Err(pcap::Error::PcapError(e)) if e.contains("Packets are not available") => {
                thread::sleep (Duration::from_micros(500));
            }
            Err(pcap::Error::TimeoutExpired) => {
                thread::sleep (Duration::from_micros(500));
            }
            Err(pcap::Error::PcapError(e)) if e.contains("Interrupted") => {
                warn!("Capture interrupted cleanly");
                break;
            }
            Err(pcap::Error::PcapError(e)) if e.contains("Operation not permitted") => {
                error!("Missing privileges. Try:\nsudo setcap cap_net_raw,cap_net_admin=eip ./your_binary");
                break;
            }

            Err(e) => {
                error!("Unknown error: {:?}", e);
                break;
            }
        }
        
    }
    info!("Capture completed. Total packets: {}", count);
    Ok(())
}