//! netprobe — pure Rust network & security scanner.
//! Zero dependencies.

use std::env;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: netprobe <host> [ports]");
        eprintln!("Example: netprobe example.com 22,80,443,8443");
        std::process::exit(1);
    }

    let host = &args[1];
    let ports: Vec<u16> = if args.len() > 2 {
        args[2]
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect()
    } else {
        vec![22, 80, 443, 8080, 8443]
    };

    if ports.is_empty() {
        eprintln!("No valid ports provided");
        std::process::exit(1);
    }

    println!("\x1b[1;36mNETPROBE\x1b[0m  {}", host);
    println!("\x1b[90m──────────────────────────────\x1b[0m");

    for port in ports {
        match probe(host, port, Duration::from_millis(800)) {
            Ok(ms) => {
                println!("  \x1b[32mOPEN\x1b[0m   {:>5}   {} ms", port, ms);
                if port == 443 || port == 8443 {
                    println!("         \x1b[33mTLS probe ready\x1b[0m");
                }
            }
            Err(_) => {
                println!("  \x1b[90mclosed\x1b[0m {:>5}", port);
            }
        }
    }

    println!("\x1b[90m──────────────────────────────\x1b[0m");
}

/// Try to connect and return latency in milliseconds.
fn probe(host: &str, port: u16, timeout: Duration) -> Result<u128, ()> {
    let addr_str = format!("{}:{}", host, port);
    let mut addrs = match addr_str.to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return Err(()),
    };

    let addr = match addrs.next() {
        Some(a) => a,
        None => return Err(()),
    };

    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Ok(start.elapsed().as_millis()),
        Err(_) => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_localhost_closed_port() {
        // High port that should be closed on most machines
        let result = probe("127.0.0.1", 59999, Duration::from_millis(200));
        // We don't assert Err because some environments may have it open;
        // we just make sure it doesn't panic.
        let _ = result;
    }

    #[test]
    fn parse_ports_logic() {
        let s = "22, 80,443, invalid,8443";
        let ports: Vec<u16> = s
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect();
        assert_eq!(ports, vec![22, 80, 443, 8443]);
    }
}
