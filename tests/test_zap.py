#!/usr/bin/env python3

import argparse
from pprint import pprint

from modules import zap


def main():
    parser = argparse.ArgumentParser(
        description="Test the THRAGG ZAP module"
    )

    parser.add_argument(
        "--report",
        required=True,
        help="Path to ZAP JSON report"
    )

    args = parser.parse_args()

    result = zap.run(args.report)

    print("\n===== ZAP Module Result =====\n")
    pprint(result)


if __name__ == "__main__":
    main()
