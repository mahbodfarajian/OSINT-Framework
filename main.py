#!/usr/bin/env python3
"""Kali Security Toolkit - entry point."""
import argparse

from modules import common


def main() -> None:
    parser = argparse.ArgumentParser(description="Kali Security Toolkit (authorized use only)")
    parser.add_argument("--safe-mode", action="store_true",
                        help="Force safe mode: all active scanning is disabled for this session")
    args = parser.parse_args()

    common.set_safe_mode(common.load_config().get("safe_mode", True), force=args.safe_mode)
    common.log.info("Starting toolkit (safe-mode flag=%s)", args.safe_mode)

    from gui.app import App  # imported late so --help works without a display
    App().mainloop()


if __name__ == "__main__":
    main()
