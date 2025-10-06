#!/usr/bin/env python3

import sys
import subprocess
import pkg_resources
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def check_python_version():
    """Verify Python version meets minimum requirements."""
    required_version = (3, 8)
    current_version = sys.version_info[:2]

    if current_version < required_version:
        logger.error(
            f"Python {required_version[0]}.{required_version[1]} or higher is required"
        )
        return False

    logger.info(f"Python version {sys.version.split()[0]} - OK")
    return True


def check_system_dependencies():
    """Check if required system tools are installed."""
    dependencies = {
        "tshark": "wireshark-cli",
        "dumpcap": "wireshark",
    }

    all_installed = True
    for cmd, package in dependencies.items():
        try:
            subprocess.run(["which", cmd], check=True, capture_output=True, text=True)
            logger.info(f"Found {cmd} - OK")
        except subprocess.CalledProcessError:
            logger.error(
                f"{cmd} not found. Install it using: sudo dnf install {package}"
            )
            all_installed = False

    return all_installed


def check_python_packages():
    """Verify required Python packages are installed."""
    requirements_file = Path(__file__).parent / "requirements.txt"

    if not requirements_file.exists():
        logger.error("requirements.txt not found")
        return False

    with open(requirements_file) as f:
        requirements = [
            line.strip() for line in f if line.strip() and not line.startswith("#")
        ]

    all_installed = True
    for requirement in requirements:
        try:
            pkg_resources.require(requirement)
            logger.info(f"Package {requirement} - OK")
        except pkg_resources.DistributionNotFound:
            logger.error(f"Package {requirement} is not installed")
            all_installed = False
        except pkg_resources.VersionConflict as e:
            logger.error(f"Package version conflict: {e}")
            all_installed = False

    return all_installed


def check_permissions():
    """Verify user has necessary permissions."""
    try:
        # Check if script is run with sudo/root
        if os.geteuid() != 0:
            logger.warning("Script not running with root privileges")
            logger.info("Some features may require running with sudo")
            return False

        # Check wireshark group membership
        groups_output = subprocess.run(
            ["groups"], check=True, capture_output=True, text=True
        ).stdout

        if "wireshark" not in groups_output:
            logger.warning("User is not in the wireshark group")
            logger.info("Run: sudo usermod -a -G wireshark $USER")
            return False

        logger.info("Permissions - OK")
        return True

    except Exception as e:
        logger.error(f"Error checking permissions: {e}")
        return False


def main():
    """Verify all installation requirements are met."""
    logger.info("Starting installation verification...")

    checks = [
        ("Python Version", check_python_version),
        ("System Dependencies", check_system_dependencies),
        ("Python Packages", check_python_packages),
        ("Permissions", check_permissions),
    ]

    all_passed = True
    for name, check_func in checks:
        logger.info(f"\nChecking {name}...")
        if not check_func():
            all_passed = False

    if all_passed:
        logger.info("\nAll checks passed! The tool is ready to use.")
        return 0
    else:
        logger.error("\nSome checks failed. Please address the issues above.")
        return 1


if __name__ == "__main__":
    import os

    sys.exit(main())
