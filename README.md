# BLE GATT Parser

Command-line tool to analyze and reconstruct BLE GATT communication flows from Wireshark captures.

## Features

- Chronological event timeline with relative timestamps
- Analysis of GATT operations by handle
- Reconstruction of sequential write operations
- Support for all standard GATT operations:
  - Read/Write operations
  - Notifications and Indications
  - Service Discovery
  - MTU Exchange

## Requirements

- Python 3.6+
- pyshark

## Usage

```bash
python parse_gatt.py capture.pcapng
```

## Output Format

The tool provides two views of the GATT communication:

### Communication Flow
Shows chronological sequence of GATT operations:
```
=== Communication Flow Summary ===
+0.000s Frame 100: Handle 0x0003 - Read By Type Request: UUID: 2803
+0.010s Frame 101: Handle 0x0003 - Read By Type Response: Value1
```

### Handle Analysis
Detailed breakdown of operations per handle:
```
=== Detailed Analysis by Handle ===
Handle: 0x0004
Write Request (2 operations):
  Frame 102 (Conn: 1): Data1
  Frame 104 (Conn: 1): Data2
  Combined data: Data1Data2
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request


## Support

If you find this project useful, consider supporting development:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/f0rw4rd)
