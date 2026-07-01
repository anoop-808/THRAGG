#!/usr/bin/env python3

import argparse
from pprint import pprint

from modules import nmap


def main():
    parser = argparse.ArgumentParser(
        description="Test THRAGG Nmap Module"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target IP or hostname"
    )

    args = parser.parse_args()

    result = nmap.run(args.target)

    print("\n===== Nmap Module Result =====\n")
    pprint(result)


if __name__ == "__main__":
    main()
