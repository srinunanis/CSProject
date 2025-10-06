import pyshark
import os
import subprocess
import logging
from typing import Optional


class PacketCapture:
    def __init__(
        self, interface: Optional[str] = None, bpf_filter: Optional[str] = None
    ):
        """Initialize packet capture with specified interface and filter.

        Args:
            interface: Network interface name (e.g., 'eth0', 'wlan0')
            bpf_filter: Berkeley Packet Filter string (e.g., 'tcp port 80')
        """
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.capture = None
        self.tshark_path = self._find_tshark()

    def _find_tshark(self) -> str:
        """Locate TShark executable in the system.

        Returns:
            str: Path to TShark executable

        Raises:
            FileNotFoundError: If TShark is not found
        """
        try:
            result = subprocess.run(
                ["which", "tshark"], capture_output=True, text=True, check=True
            )
            tshark_path = result.stdout.strip()
            if os.path.exists(tshark_path) and os.access(tshark_path, os.X_OK):
                return tshark_path
        except subprocess.CalledProcessError:
            # Check common paths if 'which' fails
            common_paths = [
                "/usr/bin/tshark",
                "/usr/local/bin/tshark",
                "/usr/sbin/tshark",
            ]
            for path in common_paths:
                if os.path.exists(path) and os.access(path, os.X_OK):
                    return path

        raise FileNotFoundError(
            "TShark not found. Please install it using: sudo dnf install wireshark-cli"
        )

    def _verify_interface(self) -> bool:
        """Verify if the specified interface exists and is up.

        Returns:
            bool: True if interface is valid and up, False otherwise
        """
        try:
            result = subprocess.run(
                ["ip", "link", "show", self.interface],
                capture_output=True,
                text=True,
                check=True,
            )
            return "state UP" in result.stdout
        except subprocess.CalledProcessError:
            return False

    def start_capture(self):
        """Start packet capture on specified interface.

        Returns:
            pyshark.LiveCapture: Capture object

        Raises:
            ValueError: If interface is not specified or invalid
            PermissionError: If not running with required privileges
            RuntimeError: If capture fails to start
        """
        if not self.interface:
            raise ValueError("No interface specified")

        if not self._verify_interface():
            raise ValueError(f"Interface {self.interface} is not up or doesn't exist")

        if os.geteuid() != 0:
            raise PermissionError(
                "Packet capture requires root privileges. Please run with sudo."
            )

        try:
            # Create capture with minimal configuration
            self.capture = pyshark.LiveCapture(
                interface=self.interface, bpf_filter=self.bpf_filter
            )

            logging.info(f"Capture started on interface {self.interface}")
            if self.bpf_filter:
                logging.info(f"Using filter: {self.bpf_filter}")

            return self.capture

        except Exception as e:
            raise RuntimeError(f"Failed to start capture: {str(e)}")

    def stop_capture(self) -> None:
        """Stop the packet capture safely."""
        if self.capture:
            try:
                self.capture.close()
                logging.info("Capture stopped")
            except Exception as e:
                logging.error(f"Error while stopping capture: {str(e)}")

    def get_interface_info(self) -> str:
        """Get detailed information about the current interface.

        Returns:
            str: Interface information
        """
        if not self.interface:
            return "No interface specified"

        try:
            result = subprocess.run(
                ["ip", "addr", "show", self.interface],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Unable to get information for interface {self.interface}: {str(e)}"
