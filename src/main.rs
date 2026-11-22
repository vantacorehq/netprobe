//! netprobe — pure Rust network scanner.

use std::env;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("netprobe <host> [ports]");
        println!("example: netprobe example.com 80,443,22");
        return;
    }

    let host = &args[1];
    let ports: Vec<u16> = if args.len() > 2 {
        args[2]
            .split(',')
            .filter_map(|p| p.parse().ok())
            .collect()
    } else {
        vec![22, 80, 443, 8080, 8443]
    };

    println!("\x1b[1;36mNETPROBE\x1b[0m  {}", host);
    println!("\x1b[90m──────────────────────────────\x1b[0m");

    for port in ports {
        let addr = format!("{}:{}", host, port);
        let start = Instant::now();
        match TcpStream::connect_timeout(
            &addr.to_socket_addrs().unwrap().next().unwrap(),
            Duration::from_millis(800),
        ) {
            Ok(mut stream) => {
                let ms = start.elapsed().as_millis();
                println!("  \x1b[32mOPEN\x1b[0m   {:>5}   {} ms", port, ms);

                if port == 443 || port == 8443 {
                    // minimal TLS handshake probe (not full verify)
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    // In production send ClientHello and parse cert
                    println!("         \x1b[33mSSL probe ready (extend with ClientHello)\x1b[0m");
                }
            }
            Err(_) => {
                println!("  \x1b[90mclosed\x1b[0m {:>5}", port);
            }
        }
    }

    println!("\x1b[90m──────────────────────────────\x1b[0m");
    println!("DNS / cert expiry: extend with raw queries or system resolver");
}
