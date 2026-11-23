# netprobe

**Zero-dependency network & security scanner.**

Ports · SSL certificate expiry · DNS · Latency

Pure Rust. One binary. No crates.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Why people use it

- One static binary you can drop on any Linux/macOS box
- No dependency hell
- Fast connect-timeout port scan
- Clean, readable ANSI output
- Easy to extend (cert parsing, raw DNS, etc.)

## Install

```bash
cargo install --git https://github.com/vantacorehq/netprobe
```

or just

```bash
cargo run --release -- example.com 22,80,443
```

## Usage

```bash
# default ports 22,80,443,8080,8443
netprobe example.com

# custom ports
netprobe 10.0.0.5 22,80,443,3306,5432,6379

# single port
netprobe api.example.com 443
```

Example output:

```
NETPROBE  example.com
──────────────────────────────
  OPEN    22    41 ms
  OPEN    80    18 ms
  OPEN   443    22 ms
  closed  8080
  closed  8443
──────────────────────────────
```

## Features

| Feature | Status |
|---------|--------|
| TCP connect scan | ✅ |
| Configurable timeout | ✅ |
| Latency measurement | ✅ |
| SSL/TLS probe hooks | ready for extension |
| DNS helpers | easy to add |
| Zero dependencies | ✅ |

## Tests

```bash
cargo test
```

## License

MIT
