#!/usr/bin/env python3
"""Main entry point for the Secure Password Manager application."""

import logging
import os
import signal
import sys
from pathlib import Path
from typing import Optional

from handlers import (
    handle_main_menu,
    handle_signal
)
from utils import (
    setup_logging,
    print_welcome,
    validate_file,
    open_vault,
    SUFFIX
)
from password_manager import SecurePasswordManager

logger = logging.getLogger(os.path.splitext(__file__)[0].split(os.sep)[-1])

# Global variable to store SecurePasswordManager instance for signal handler
_spm_instance: Optional[SecurePasswordManager] = None


def signal_handler(signum, frame):
    """Handle interrupt signals."""
    handle_signal(_spm_instance)


def main() -> None:
    """Main application entry point."""

    logger.debug("Main application entry point")

    if len(sys.argv) < 2:
        print("Usage: python SecPwdMgr.py <vault_file>\n")
        print("Example: python SecPwdMgr.py vault.spm")
        print("Note: The .spm extension will be added automatically if it is not already present.")
        sys.exit(1)

    file_path = str(sys.argv[1])

    logger.info("Starting application")
    print_welcome()

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Resolve and normalize the file path
    file_path = Path(file_path).expanduser().absolute()

    # Add .spm extension if not already present
    if file_path.suffix != SUFFIX:
        file_path = file_path.with_suffix(SUFFIX)

    # Convert to string
    file_path = str(file_path)

    # Check file permissions if file exists
    if Path(file_path).exists():
        perm_error = validate_file(file_path)
        if perm_error:
            logger.error(perm_error)
            print(f"Error: {perm_error}")
            sys.exit(1)

    # Open vault
    spm = open_vault(file_path)
    if spm is None:
        logger.error("Failed to open vault")
        return

    # Go to main menu
    handle_main_menu(spm)

if __name__ == "__main__":
    setup_logging()
    main()