# Network Packet Analysis Tool

## Overview

A robust, real-time network packet analysis tool designed for Linux systems, particularly optimized for Fedora. This tool provides comprehensive network traffic monitoring, threat detection, and security analysis capabilities using Python and TShark.

## Features

### Core Functionality
- Real-time packet capture and analysis
- Customizable BPF (Berkeley Packet Filter) support
- Multiple interface monitoring
- Threat detection and reporting
- TCP/UDP traffic analysis
- Blacklist-based IP filtering

### Security Features
- SYN scan detection
- DNS amplification attack detection
- Suspicious port monitoring
- Private-to-public IP communication tracking
- Blacklist management with remote updates
- Customizable threat detection rules

### Monitoring Capabilities
- Port scanning detection
- Suspicious service detection (SSH, Telnet, SMB, RDP, etc.)
- DNS query analysis
- Traffic pattern analysis
- Real-time threat alerting

## Prerequisites

### System Requirements
- Linux operating system (Tested on Fedora)
- Python 3.8 or higher
- Root/sudo privileges for packet capture

### Required Packages
```bash
# System packages
sudo dnf install wireshark wireshark-cli tshark python3-devel libpcap-devel

# Python packages
pip install pyshark requests
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/network-packet-analysis.git
cd network-packet-analysis
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up permissions:
```bash
sudo usermod -a -G wireshark $USER
sudo chmod +x /usr/bin/dumpcap
```

4. Log out and log back in for group changes to take effect

## Usage

### Basic Command
```bash
sudo python3 main.py --interface <interface_name> --filter "tcp" --output threats.log
```

### Command Line Arguments
- `--interface`: Network interface to monitor (required)
- `--filter`: BPF filter string (default: "tcp")
- `--output`: Output file for threat logs (default: threats.log)
- `--debug`: Enable debug logging

### Examples

1. Monitor HTTPS traffic:
```bash
sudo python3 main.py --interface eth0 --filter "tcp port 443" --output https_threats.log
```

2. Monitor all TCP traffic with debug info:
```bash
sudo python3 main.py --interface wlan0 --filter "tcp" --output tcp_threats.log --debug
```

3. Monitor specific IP range:
```bash
sudo python3 main.py --interface eth0 --filter "net 192.168.1.0/24" --output local_threats.log
```

## Project Structure

### Core Components

1. `main.py`
   - Entry point of the application
   - Command-line argument parsing
   - Signal handling and program flow control

2. `capture.py`
   - Network interface management
   - Packet capture configuration
   - TShark integration

3. `analysis.py`
   - Threat detection logic
   - IP blacklist management
   - Traffic pattern analysis

4. `reporting.py`
   - Threat logging and reporting
   - Output file management
   - Event documentation

## Threat Detection Capabilities

### IP-Based Detection
- Blacklist matching
- Private-to-public communication monitoring
- Suspicious IP pattern recognition

### Protocol-Based Detection
- TCP flags analysis
- UDP packet inspection
- DNS query validation

### Service-Based Detection
Monitors suspicious activity on common ports:
- SSH (22)
- Telnet (23)
- SMB (445)
- RDP (3389)
- VNC (5900)
- Known malware ports

## Configuration

### Blacklist Management
The tool maintains an IP blacklist from multiple sources:
- Remote blacklist updates
- Local static entries
- Dynamic additions based on detected threats

### Logging Configuration
- Standard logging: Basic threat information
- Debug logging: Detailed packet analysis
- Custom output formats available

## Troubleshooting

### Common Issues

1. Permission Denied
```bash
sudo chmod +x main.py
sudo usermod -a -G wireshark $USER
```

2. TShark Not Found
```bash
sudo dnf install wireshark-cli
```

3. Interface Not Found
```bash
ip link show  # List available interfaces
```

### Debug Mode
Enable debug logging for detailed information:
```bash
sudo python3 main.py --interface eth0 --debug
```

## Security Considerations

1. Root Privileges
   - Tool requires root access for packet capture
   - Runs with minimal necessary permissions
   - Implements security best practices

2. Data Privacy
   - No packet payload storage
   - Configurable logging levels
   - Secure handling of sensitive information

3. System Impact
   - Minimal resource utilization
   - Configurable capture filters
   - Graceful shutdown handling

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests if applicable
5. Submit a pull request

### Development Guidelines
- Follow PEP 8 style guide
- Add type hints to new functions
- Include docstrings for all functions
- Update tests for new features

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Wireshark/TShark developers
- Python pyshark library maintainers
- Open-source IP blacklist providers

## Contact

For bugs, features, or questions:
- Create an issue in the GitHub repository
- Contact: your.email@example.com

## Version History

- v1.0.0 (2024-02-06)
  - Initial release
  - Basic packet capture and analysis
  - Threat detection implementation

- v1.1.0 (2024-02-20)
  - Enhanced threat detection
  - Improved logging
  - Bug fixes and performance improvements

## Future Enhancements

1. Planned Features
   - Machine learning-based threat detection
   - Real-time visualization
   - API integration
   - Custom rule creation interface

2. Performance Optimizations
   - Multi-threading support
   - Improved memory management
   - Faster packet processing

3. Additional Capabilities
   - Protocol analyzers
   - Custom signature support
   - Automated response actions