"""Handler functions for the Secure Password Manager application."""

import logging
import pyperclip
import sys
from typing import Optional

from dialogs import (
    dialog_main_menu,
    dialog_entry,
    dialog_add_entry,
    dialog_update_entry,
    dialog_delete_entry,
    dialog_generate_password,
    ERR_OPERATION_CANCELED
)
from utils import (
    exit_application
)
from password_manager import SecurePasswordManager

logger = logging.getLogger(__name__)

def handle_main_menu(spm: SecurePasswordManager) -> None:
    """
    Handle main menu loop.

    Args:
        spm: SecurePasswordManager instance
    """

    global _spm_instance
    _spm_instance = spm

    logger.debug("Displaying menu")
    while True:
        choice, err = dialog_main_menu()
        if err:
            if err == ERR_OPERATION_CANCELED:
                logger.info("User interrupted the prompt")
                exit_application(spm)

            logger.error(f"Error reading choice: {err}")
            exit_application(spm)
            return

        if choice == 1:
            handle_get_entry(spm)
        elif choice == 2:
            dialog_add_entry(spm)
        elif choice == 3:
            dialog_update_entry(spm)
        elif choice == 4:
            dialog_delete_entry(spm)
        elif choice == 5:
            handle_search_entries(spm)
        elif choice == 6:
            handle_generate_password()
        elif choice == 0:
            exit_application(spm)
        else:
            print("Invalid choice. Please enter a valid choice. [0-5qQ]")

def handle_search_entries(spm: SecurePasswordManager) -> None:
    """
    Search for entries by service or username.

    Args:
        spm: SecurePasswordManager instance
    """

    # Search entries
    from utils import sanitize_input, print_entries
    logger.info("Searching entries")

    try:
        search_term = sanitize_input(input("Service or username: ").strip()) or None
    except (KeyboardInterrupt, EOFError):
        logger.info(ERR_OPERATION_CANCELED)
        return

    results = [e for e in spm.entries if (search_term is None or search_term.lower() in e['service'].lower()) or (search_term is None or search_term.lower() in e['username'].lower())]

    logger.info(f"Found {len(results)} matching entries")
    if not results:
        print("\nNo matching entries found.")
        logger.info("No matching entries found")
    else:
        print(f"\n--- Found {len(results)} matching entries ---")
        print_entries(results)


def handle_get_entry(spm: SecurePasswordManager) -> None:
    """
    List/select an entry and get the password and copy to clipboard.

    Args:
        spm: SecurePasswordManager instance
    """

    logger.info("Getting list of entries")
    entry, err = dialog_entry(spm.entries, "Select an entry to get the password or 0 to get back to the main menu")
    if err:
        if err == ERR_OPERATION_CANCELED:
            logger.info(ERR_OPERATION_CANCELED)
        else:
            logger.error(f"Error copying password {err}")
            print("Error getting password, please try again.")
        return

    try:
        pyperclip.copy(entry['password'])
        print("Password copied to clipboard!")
        logger.info(f"Password copied to clipboard for {entry['service']}")
    except Exception as e:
        logger.error(f"Error copying password to clipboard: {e}")
        print("Error copying password to clipboard, please try again.")
        logger.error(f"Error copying password to clipboard for {entry['service']}: {e}")


def handle_signal(spm: Optional[SecurePasswordManager]) -> None:
    """
    Handle interrupt signals and save data before exiting.

    Args:
        spm: SecurePasswordManager instance to save
    """

    print("\nReceived interrupt signal .. exiting and saving entries...")
    logger.info("Received interrupt signal")
    if spm is not None and spm.file_path:
        try:
            logger.info("Saving entries...")
            spm.save_to_file(spm.file_path)
            logger.info(f"Passwords saved successfully to {spm.file_path}!")
        except Exception as e:
            logger.error(f"Error saving passwords: {e}")
            print("Error saving passwords, please try again.")
    else:
        logger.info("Password manager is not initialized, nothing to save.")
    logger.info("Application exiting due to interrupt signal")
    sys.exit(0)


def handle_generate_password() -> None:
    """Generate a random password and copy to clipboard."""

    logger.info("Generating password")
    password, err = dialog_generate_password()
    if err:
        if err == ERR_OPERATION_CANCELED:
            logger.info(ERR_OPERATION_CANCELED)
        else:
            logger.error(f"Error generating password: {err}")
        return

    if password:
        try:
            pyperclip.copy(password)
            print("Generated password copied to clipboard!")
            logger.info("Generated password copied to clipboard")
        except Exception as e:
            logger.error(f"Error copying password to clipboard: {e}")
            print("Error copying password to clipboard, please try again.")