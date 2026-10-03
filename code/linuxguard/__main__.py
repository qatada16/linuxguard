"""Development commands; the monitoring pipeline is not implemented yet."""

import argparse
from pathlib import Path

from linuxguard.config import load_config


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check-config"])
    parser.add_argument("--config", type=Path, default=Path("config/linuxguard.yaml"))
    args = parser.parse_args()
    try:
        config = load_config(args.config)
    except ValueError as exc:
        parser.exit(2, f"Configuration error: {exc}\n")
    print(f"Configuration valid: {args.config.resolve()}")
    print(f"SSH target: {config['collector']['ssh_host']}")
    print(f"Database: {config['storage']['database']}")
    print(f"AI mode: {config['ai']['mode']}")
    print("Foundation only: no collection or detection was run.")


if __name__ == "__main__":
    main()
