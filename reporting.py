import os
import logging
from datetime import datetime


class Reporter:
    def __init__(self, output_file=None):
        self.output_file = output_file
        if output_file:
            try:
                # Ensure the directory exists
                directory = os.path.dirname(os.path.abspath(output_file))
                if directory:
                    os.makedirs(directory, exist_ok=True)
                # Test if we can write to the file
                with open(output_file, "a") as f:
                    pass
            except (PermissionError, OSError) as e:
                logging.error(f"Cannot access output file {output_file}: {str(e)}")
                logging.info("Falling back to console output")
                self.output_file = None

    def report_threats(self, threats):
        if not threats:
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_lines = [f"=== Threat Report {timestamp} ==="]
        report_lines.extend(threats)
        report_lines.append("=" * 40 + "\n")
        report = "\n".join(report_lines)

        if self.output_file:
            try:
                with open(self.output_file, "a") as f:
                    f.write(report)
            except (PermissionError, OSError) as e:
                logging.error(f"Failed to write to {self.output_file}: {str(e)}")
                print(report)  # Fallback to console output
        else:
            print(report)

    def write_summary(self, summary_data):
        """
        Write a summary of threat analysis

        Args:
            summary_data (dict): Dictionary containing summary information
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary_lines = [
            f"\n=== Summary Report {timestamp} ===",
            f"Total packets analyzed: {summary_data.get('total_packets', 0)}",
            f"Total threats detected: {summary_data.get('total_threats', 0)}",
            f"Unique malicious IPs: {len(summary_data.get('malicious_ips', []))}",
            "Malicious IPs detected:",
        ]

        for ip in summary_data.get("malicious_ips", []):
            summary_lines.append(f"  - {ip}")

        summary_lines.append("=" * 40 + "\n")
        summary = "\n".join(summary_lines)

        if self.output_file:
            try:
                with open(self.output_file, "a") as f:
                    f.write(summary)
            except (PermissionError, OSError) as e:
                logging.error(
                    f"Failed to write summary to {self.output_file}: {str(e)}"
                )
                print(summary)
        else:
            print(summary)

    def cleanup(self):
        """
        Perform any necessary cleanup operations
        """
        # Currently no cleanup needed, but method included for future use
        pass
