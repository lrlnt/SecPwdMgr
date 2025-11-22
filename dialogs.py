"""User dialog functions for interactive input."""

import getpass
import logging
from typing import Optional, Tuple

from password_manager import (
    SecurePasswordManager,
    MIN_LENGTH,
    MAX_LENGTH
)

logger = logging.getLogger(__name__)

ERR_READING_PASSWORD = "Error reading password:"
ERR_OPERATION_CANCELED = "Operation cancelled by user"
ERR_PROMPT_FAILED = "Dialog failed"
ERR_PASSWORDS_DO_NOT_MATCH = "Passwords do not match"
ERR_PASSWORD_TOO_SHORT = f"INSECURE: Password must have more than {MIN_LENGTH} characters"
ERR_PASSWORD_TOO_LONG = f"RESTRICTED: Password must have less than {MAX_LENGTH} characters"
ERR_PASSWORD_LENGTH_INVALID = f"RESTRICTED: Password length must be between {MIN_LENGTH} and {MAX_LENGTH} characters"
ERR_PASSWORD_LENGTH_EMPTY = "INSECURE: Password length cannot be empty"

def dialog_create_master_password() -> Tuple[Optional[str], Optional[str]]:
    """
    Dialog for creating a master password for the file.

    Returns:
        Tuple of (master_password, error_message)
    """

    while True:
        try:
            master_password = getpass.getpass("Master Password: ")
            if len(master_password) < MIN_LENGTH:
                print(ERR_PASSWORD_TOO_SHORT)
                continue
            elif len(master_password) > MAX_LENGTH:
                print(ERR_PASSWORD_TOO_LONG)
                continue

            confirm_password = getpass.getpass("Confirm Master Password: ")
            if master_password != confirm_password:
                print(ERR_PASSWORDS_DO_NOT_MATCH)
                continue

            return master_password, None
        except KeyboardInterrupt:
            return None, ERR_OPERATION_CANCELED
        except EOFError:
            return None, ERR_OPERATION_CANCELED


def dialog_verify_master_password() -> Tuple[Optional[str], Optional[str]]:
    """
    Dialog for verifying the master password.

    Returns:
        Tuple of (master_password, error_message)
    """

    while True:
        try:
            master_password = getpass.getpass("Master Password: ")
            if len(master_password) < 1:
                print(ERR_PASSWORD_TOO_SHORT)
                continue
            elif len(master_password) > MAX_LENGTH:
                print(ERR_PASSWORD_TOO_LONG)
                continue
            return master_password, None
        except KeyboardInterrupt:
            return None, ERR_OPERATION_CANCELED
        except EOFError:
            return None, ERR_OPERATION_CANCELED


def dialog_entry(entries: list[dict], label: str) -> Tuple[Optional[dict], Optional[str]]:
    """
    Dialog for selecting an entry from a list.

    Args:
        entries: List of entry dictionaries
        label: Prompt label

    Returns:
        Tuple of (selected_entry, error_message)
    """

    from utils import print_entries

    if not entries:
        return None, "No entries available"

    print(f"\n{label}")
    print_entries(entries)

    while True:
        try:
            choice = input("\nSelect entry (number) or 0 to get back to the main menu: ").strip()
            index = int(choice) - 1
            if 0 <= index < len(entries):
                return entries[index], None
            elif index == -1:
                return None, ERR_OPERATION_CANCELED
            else:
                print("Invalid selection. Please try again.")
        except ValueError:
            print("Please enter a valid number.")
        except (KeyboardInterrupt, EOFError):
            return None, ERR_OPERATION_CANCELED


def dialog_main_menu() -> Tuple[int, Optional[str]]:
    """
    Dialog for main menu selection.

    Returns:
        Tuple of (choice_number, error_message)
    """

    print("\n" + "=" * 42)
    print("Main Menu")
    print("=" * 42)
    print("1. List/get entries")
    print("2. Create entry")
    print("3. Update entry")
    print("4. Delete entry")
    print("5. Search entries")
    print("6. Generate password and copy to clipboard")
    print("0. Exit")
    print("=" * 42)

    while True:
        try:
            choice = input("Select option (0-6): ").strip()
            choice_num = int(choice)
            if 0 <= choice_num <= 6:
                return choice_num, None
            else:
                print("Invalid choice. Please enter a number between 0 and 6.")
        except ValueError:
            print("Please enter a valid number.")
        except KeyboardInterrupt:
            return -1, ERR_OPERATION_CANCELED
        except EOFError:
            return -1, ERR_OPERATION_CANCELED


def dialog_yes_no(label: str) -> Tuple[bool, Optional[str]]:
    """
    Dialog for yes/no confirmation.

    Args:
        label: Prompt label

    Returns:
        Tuple of (is_yes, error_message)
    """

    while True:
        try:
            response = input(f"{label} (yes/no): ").strip().lower()
            if response in ("yes", "y"):
                return True, None
            elif response in ("no", "n"):
                return False, None
            else:
                print("Please enter 'yes' or 'no'.")
        except KeyboardInterrupt:
            return False, ERR_OPERATION_CANCELED
        except EOFError:
            return False, ERR_OPERATION_CANCELED

def dialog_add_entry(spm: SecurePasswordManager) -> None:
    """
    Add a new entry dialog.

    Args:
        spm: SecurePasswordManager instance
    """

    from utils import sanitize_input

    logger.info("Adding new entry")
    try:
        service_name = sanitize_input(input("Enter service: ").strip())
        if not service_name:
            print("Service cannot be empty")
            return
    except (KeyboardInterrupt, EOFError):
        logger.info(ERR_OPERATION_CANCELED)
        return

    try:
        username = sanitize_input(input("Enter username: ").strip())
    except (KeyboardInterrupt, EOFError):
        logger.info(ERR_OPERATION_CANCELED)
        return

    try:
        yesno, err = dialog_yes_no("Would you like to generate a password or input your own?")
    except (KeyboardInterrupt, EOFError):
        logger.info(ERR_OPERATION_CANCELED)
        return

    if yesno:
        password, err = dialog_generate_password()
        if err:
            logger.error(f"Error generating password: {err}")
            print("Error generating password, please try again.")
            return
    else:
        try:
            password = sanitize_input(getpass.getpass("Enter password: "))
        except (KeyboardInterrupt, EOFError):
            logger.info(ERR_OPERATION_CANCELED)
            return

    spm.add_entry(service_name, username, password)
    try:
        spm.save_to_file(spm.file_path)
    except Exception as e:
        logger.error(f"Error saving entry: {e}")
        print("Error saving entry, please try again.")
        return

    if len(password) < MIN_LENGTH:
        print("WARNING: Password is less than 8 characters. Consider using a longer password.")
    print("Entry added successfully!")


def dialog_delete_entry(spm: SecurePasswordManager) -> None:
    """
    Delete an entry from the password manager.

    Args:
        pm: SecurePasswordManager instance
    """

    logger.info("Deleting entry")
    entry, err = dialog_entry(spm.entries, "Select an entry to delete or CTRL+C to cancel")
    if err:
        if err == ERR_OPERATION_CANCELED:
            logger.info("User interrupted the prompt during deleting entry")
        else:
            logger.error(f"{ERR_READING_PASSWORD} {err}")
            print(f"{ERR_READING_PASSWORD} {err}")
        return

    if entry:
        try:
            spm.entries.remove(entry)
            spm.save_to_file(spm.file_path)
            logger.info(f"Entry {entry['service']} deleted successfully")
            print("Entry deleted successfully!")
        except ValueError:
            logger.info("Entry not found")
            print("Entry not found!")
        except Exception as e:
            logger.error(f"Error deleting entry: {e}")
            print("Error deleting entry, please try again.")


def dialog_update_entry(spm: SecurePasswordManager) -> None:
    """
    Update an existing entry in the password manager.

    Args:
        spm: SecurePasswordManager instance
    """

    from utils import sanitize_input
    logger.info("Updating entry")
    entry, err = dialog_entry(spm.entries, "Select an entry to update")
    if err:
        if err == ERR_OPERATION_CANCELED:
            logger.info(ERR_OPERATION_CANCELED)
        else:
            logger.error(f"{ERR_READING_PASSWORD} {err}")
            print("Error updating entry, please try again.")
        return

    if not entry:
        return

    print("\nCurrent values:")
    print(f"  Service: {entry['service']}")
    print(f"  Username: {entry['username']}")
    print(f"  Password: {'*' * len(entry['password'])}")

    # Update service
    try:
        new_service = sanitize_input(input(f"Enter new service (press Enter to keep '{entry['service']}'): ").strip())
        if new_service:
            entry['service'] = new_service
    except (KeyboardInterrupt, EOFError):
        logger.info(ERR_OPERATION_CANCELED)
        return

    # Update username
    try:
        new_username = sanitize_input(input(f"Enter new username (press Enter to keep '{entry['username']}'): ").strip())
        if new_username:
            entry['username'] = new_username
    except (KeyboardInterrupt, EOFError):
        logger.info(ERR_OPERATION_CANCELED)
        return

    # Update password
    try:
        new_password = sanitize_input(getpass.getpass("Enter new password (press Enter to keep current): "))
        if new_password:
            entry['password'] = new_password
    except (KeyboardInterrupt, EOFError):
        logger.info(ERR_OPERATION_CANCELED)
        return

    try:
        spm.save_to_file(spm.file_path)
    except Exception as e:
        logger.error(f"Error saving updated entry: {e}")
        return

    logger.debug("Entry updated successfully")
    print("Entry updated successfully!")


def dialog_generate_password() -> Tuple[Optional[str], Optional[str]]:
    """ Dialog for password generation parameters and generate password. """

    from utils import password_generator
    logger.info("Generating password")

    # Prompt for password length
    while True:
        try:
            length_str = input(f"Password Length ({MIN_LENGTH}-{MAX_LENGTH}): ").strip()
            if not length_str:
                print(ERR_PASSWORD_LENGTH_EMPTY)
                continue
            length = int(length_str)
            if length < MIN_LENGTH or length > MAX_LENGTH:
                print(ERR_PASSWORD_LENGTH_INVALID)
                continue
            break
        except ValueError:
            print(ERR_PASSWORD_LENGTH_INVALID)
        except (KeyboardInterrupt, EOFError):
            logger.info(ERR_OPERATION_CANCELED)
            return None, ERR_OPERATION_CANCELED

    # Dialog for including uppercase letters
    include_uppercase, err = dialog_yes_no("Include Uppercase Letters")
    if err:
        return None, err

    # Dialog for including numbers
    include_numbers, err = dialog_yes_no("Include Numbers")
    if err:
        return None, err

    # Dialog for including symbols
    include_symbols, err = dialog_yes_no("Include Symbols")
    if err:
        return None, err

    try:
        password = password_generator(length, include_uppercase, include_numbers, include_symbols)
        return password, None
    except Exception as e:
        return None, str(e)

