#!/usr/bin/env python3

import argparse
import logging
import os
import signal
import sys
from capture import PacketCapture
from analysis import ThreatAnalyzer
from reporting import Reporter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    logger.info("Received interrupt signal. Shutting down...")
    sys.exit(0)


def get_available_interfaces():
    """Get list of available network interfaces."""
    try:
        interfaces = []
        with open("/proc/net/dev") as f:
            for line in f:
                if ":" in line:
                    iface = line.split(":")[0].strip()
                    if iface != "lo":  # Exclude loopback
                        interfaces.append(iface)
        return interfaces
    except Exception as e:
        logger.error(f"Failed to get network interfaces: {e}")
        return []


def validate_interface(interface):
    """Validate if interface exists and is up."""
    if not interface:
        return False
    try:
        with open(f"/sys/class/net/{interface}/operstate") as f:
            state = f.read().strip()
            return state.lower() == "up"
    except Exception:
        return False


def main():
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Get available interfaces
    interfaces = get_available_interfaces()
    if not interfaces:
        logger.error("No network interfaces found")
        sys.exit(1)

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Network Packet Analysis Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--interface",
        choices=interfaces,
        required=True,
        help="Network interface to capture from",
    )
    parser.add_argument(
        "--filter", default="tcp", help='BPF filter (e.g., "tcp port 80")'
    )
    parser.add_argument(
        "--output", default="threats.log", help="Output file for threat reports"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Set debug logging if requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Validate interface
    if not validate_interface(args.interface):
        logger.error(f"Interface {args.interface} is not up or doesn't exist")
        sys.exit(1)

    # Check if we have necessary permissions
    if os.geteuid() != 0:
        logger.error("This program requires root privileges. Please run with sudo.")
        sys.exit(1)

    # Initialize components
    capturer = None
    reporter = None

    try:
        logger.info(f"Starting Packet Analysis Tool on interface {args.interface}")

        # Initialize components
        capturer = PacketCapture(interface=args.interface, bpf_filter=args.filter)
        analyzer = ThreatAnalyzer()
        reporter = Reporter(output_file=args.output)

        # Start packet capture
        capture = capturer.start_capture()
        logger.info("Packet capture started successfully")

        # Main capture loop
        packet_count = 0
        for packet in capture.sniff_continuously():
            packet_count += 1
            if packet_count % 100 == 0:
                logger.debug(f"Processed {packet_count} packets")

            threats = analyzer.analyze_packet(packet)
            if threats:
                logger.warning(f"Threats detected: {threats}")
                reporter.report_threats(threats)

    except KeyboardInterrupt:
        logger.info("Capture stopped by user")
    except PermissionError as pe:
        logger.error(f"Permission error: {pe}")
        logger.info("Try running the script with sudo")
    except Exception as e:
        logger.error(f"Error during capture: {e}")
        if args.debug:
            logger.exception("Detailed error information:")
    finally:
        # Cleanup
        if capturer:
            try:
                capturer.stop_capture()
            except Exception as e:
                logger.error(f"Error stopping capture: {e}")

        if reporter:
            try:
                reporter.cleanup()
            except Exception as e:
                logger.error(f"Error during cleanup: {e}")


if __name__ == "__main__":
    main()
