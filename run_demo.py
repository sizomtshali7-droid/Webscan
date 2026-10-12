"""
run_demo.py - runs the whole Webscan demo with one command.

It starts the practice website in weak mode, scans it, stops it, then does the
same for the fixed mode. Reports are saved in the "reports" folder.

Usage:  python run_demo.py            (uses port 5050)
        python run_demo.py --port 5100
"""

import argparse
import os
import subprocess
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))


def wait_until_up(url, seconds=15):
    for _ in range(seconds * 4):
        try:
            requests.get(url, timeout=1)
            return True
        except requests.RequestException:
            time.sleep(0.25)
    return False


def run_mode(mode, port, report):
    url = "http://127.0.0.1:%d" % port
    print("\n=== Practice website: %s version ===" % mode.upper())
    # sys.executable = the same Python that is running this script
    # (so the virtual environment and its packages are used).
    site = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "practice_app.py"), "--mode", mode, "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_until_up(url):
            print("The practice website did not start. Is port %d already in use?" % port)
            return None
        scan = subprocess.run(
            [sys.executable, os.path.join(HERE, "webscan.py"), url, "--report", report],
            capture_output=True, text=True)
        result = [line for line in scan.stdout.splitlines() if line.startswith("- Result:")]
        print(result[0] if result else scan.stdout + scan.stderr)
        print("Report saved to %s" % report)
        return scan.returncode
    finally:
        site.terminate()
        site.wait()


def main():
    parser = argparse.ArgumentParser(description="Run the Webscan demo (weak, then fixed).")
    parser.add_argument("--port", type=int, default=5050)
    args = parser.parse_args()

    os.makedirs(os.path.join(HERE, "reports"), exist_ok=True)
    weak = run_mode("weak", args.port, os.path.join("reports", "webscan_report_weak.md"))
    fixed = run_mode("fixed", args.port, os.path.join("reports", "webscan_report_fixed.md"))

    print("\n=== Summary ===")
    print("Weak version:  %s" % ("some checks failed (expected)" if weak == 1 else "unexpected result"))
    print("Fixed version: %s" % ("all checks passed (expected)" if fixed == 0 else "unexpected result"))
    return 0 if (weak == 1 and fixed == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
