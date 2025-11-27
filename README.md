# Shai-Hulud Scanner

Ultra-fast malware scanner for detecting the Shai-Hulud v2 npm supply chain attack.

## Install

```bash
go install github.com/drpaneas/shai-hulud-scanner@latest
```

## Usage

```bash
shai-hulud-scanner scan              # Scan current directory
shai-hulud-scanner scan --home       # Scan home directory
shai-hulud-scanner scan --full       # Full scan (disk + network + history)
shai-hulud-scanner scan -p /path     # Scan specific path
```

## License

MIT

