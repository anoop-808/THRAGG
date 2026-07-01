#!/usr/bin/env python3

import argparse
from pprint import pprint

from modules import logs


def main():
    parser = argparse.ArgumentParser(
        description="Test the THRAGG Logs module"
    )

    parser.add_argument(
        "--log",
        required=True,
        help="Path to auth.log"
    )

    args = parser.parse_args()

    result = logs.run(args.log)

    print("\n===== Logs Module Result =====\n")
    pprint(result)


if __name__ == "__main__":
    main()
