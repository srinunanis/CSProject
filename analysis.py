import requests
import logging
from typing import List, Optional
import socket
import ipaddress


class ThreatAnalyzer:
    def __init__(self):
        """Initialize the ThreatAnalyzer with an IP blacklist."""
        self.logger = logging.getLogger(__name__)
        self.blacklist = self.load_blacklist()
        self.suspicious_ports = {
            22: "SSH",
            23: "Telnet",
            445: "SMB",
            3389: "RDP",
            4444: "Possible Metasploit",
            4899: "Radmin",
            5900: "VNC",
        }

    def load_blacklist(self) -> List[str]:
        """Load blacklisted IPs from remote source with fallback to default list."""
        default_blacklist = [
            "192.168.1.1",  # Example malicious IPs
            "10.0.0.1",
            "172.67.128.193",
            "104.21.1.70",
        ]

        try:
            response = requests.get(
                "https://raw.githubusercontent.com/bitwire-it/ipblocklist/refs/heads/main/inbound.txt",
                timeout=5,
            )
            if response.status_code == 200:
                ips = response.text.splitlines()
                # Validate IPs before adding them
                valid_ips = [ip for ip in ips if self.is_valid_ip(ip)]
                self.logger.info(f"Loaded {len(valid_ips)} IPs from remote blacklist")
                return valid_ips + default_blacklist
        except Exception as e:
            self.logger.warning(f"Failed to load remote blacklist: {e}")

        self.logger.info("Using default blacklist")
        return default_blacklist

    def is_valid_ip(self, ip: str) -> bool:
        """Validate if a string is a valid IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def analyze_packet(self, packet) -> List[str]:
        """
        Analyze a packet for potential threats.

        Args:
            packet: Packet object from pyshark

        Returns:
            List of threat descriptions if threats are found
        """
        threats = []

        try:
            # Check for IP-based threats
            if hasattr(packet, "ip"):
                threats.extend(self._check_ip_threats(packet))

            # Check for TCP-based threats
            if hasattr(packet, "tcp"):
                threats.extend(self._check_tcp_threats(packet))

            # Check for UDP-based threats
            if hasattr(packet, "udp"):
                threats.extend(self._check_udp_threats(packet))

        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")

        return threats

    def _check_ip_threats(self, packet) -> List[str]:
        """Check for IP-based threats."""
        threats = []

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst

        if src_ip in self.blacklist:
            threats.append(f"Blacklisted source IP detected: {src_ip}")
        if dst_ip in self.blacklist:
            threats.append(f"Blacklisted destination IP detected: {dst_ip}")

        # Check for private IP communication to public IP
        if self._is_private_ip(src_ip) and not self._is_private_ip(dst_ip):
            threats.append(f"Private to public communication: {src_ip} -> {dst_ip}")

        return threats

    def _check_tcp_threats(self, packet) -> List[str]:
        """Check for TCP-based threats."""
        threats = []

        # Check for SYN scan
        if packet.tcp.flags_syn == "1" and packet.tcp.flags_ack == "0":
            threats.append(f"Potential SYN scan from {packet.ip.src}")

        # Check for suspicious ports
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)

        for port, service in self.suspicious_ports.items():
            if src_port == port or dst_port == port:
                threats.append(f"Suspicious {service} traffic detected on port {port}")

        return threats

    def _check_udp_threats(self, packet) -> List[str]:
        """Check for UDP-based threats."""
        threats = []

        if hasattr(packet, "udp"):
            # Check for potential DNS amplification
            if hasattr(packet, "dns") and int(packet.udp.length) > 512:
                threats.append("Potential DNS amplification attack detected")

            # Check for suspicious UDP ports
            src_port = int(packet.udp.srcport)
            dst_port = int(packet.udp.dstport)

            if src_port == 53 or dst_port == 53:  # DNS
                if hasattr(packet, "dns") and hasattr(packet.dns, "qry_name"):
                    if len(packet.dns.qry_name) > 255:
                        threats.append("Suspicious long DNS query detected")

        return threats

    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is private."""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def update_blacklist(self, new_ips: List[str]) -> None:
        """Update the blacklist with new IPs."""
        valid_ips = [ip for ip in new_ips if self.is_valid_ip(ip)]
        self.blacklist.extend(valid_ips)
        self.blacklist = list(set(self.blacklist))  # Remove duplicates
        self.logger.info(f"Added {len(valid_ips)} new IPs to blacklist")
