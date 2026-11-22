# netprobe

Zero-dependency network and security scanner.

Pure Rust. Ports · SSL cert expiry · DNS · latency.

## Why DevOps and security teams like it

One binary. No crates. Checks what is actually open, when certificates die, and how slow the path is.

## Usage

```sh
netprobe scan example.com
netprobe ports 10.0.0.1 22,80,443,8443
netprobe cert example.com:443
netprobe dns example.com
```

## Features

- TCP port scan (connect timeout)
- SSL/TLS certificate notAfter parsing (basic)
- DNS A/AAAA/MX lookup via system resolver or raw
- Round-trip latency
- Clean ANSI output

## License

MIT
