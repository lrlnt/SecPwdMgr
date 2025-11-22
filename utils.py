"""Utility functions for the SecurePasswordManager."""

import logging
import sys
import os
import pyfiglet
import secrets
import pyperclip
import re

from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from dialogs import (
    dialog_create_master_password,
    dialog_verify_master_password,
    dialog_yes_no,
    ERR_OPERATION_CANCELED,
    ERR_READING_PASSWORD,
)
from password_manager import (
    SecurePasswordManager,
    MIN_LENGTH,
    MAX_LENGTH,
    LOWERCASE,
    UPPERCASE,
    NUMBERS,
    SYMBOLS
)

logger = logging.getLogger(__name__)

SUFFIX = ".spm"
ITERATIONS = 300000

def setup_logging(level: int = logging.INFO) -> None:
    """
    Set up logging configuration.
    
    Args:
        level: Logging level
    """

    log_file = Path("./SecPwdMgr.log").resolve()

    # Configure logging
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file, mode="a"),
            #logging.StreamHandler(),
        ],
    )
    logger.debug("Logging setup complete")


def print_welcome() -> None:
    """Print welcome message."""

    logger.debug("Displaying welcome message")
    ascii_banner = pyfiglet.figlet_format("SecPwdMgr", font="slant")
    print(ascii_banner)
    print("Welcome to Secure Password Manager!\n")

def print_entries(entries: list[dict]) -> None:
    """
    Print entries.

    Args:
        entries: List of entry dictionaries
    """

    if not entries:
        return

    max_service_length = 20
    max_username_length = 20
    
    try:
        max_service_length = max(len(entry['service']) for entry in entries)
    except Exception:
        pass

    try:
        max_username_length = max(len(entry['username']) for entry in entries)
    except Exception:
        pass

    if max_service_length < 20:
        max_service_length = 20

    if max_username_length < 20:
        max_username_length = 20

    print("\n#" + " " * (len(str(len(entries))) + 1) + "Service" + " " * (max_service_length - 6) + "Username")
    print("-" * (len(str(len(entries))) + max_service_length + max_username_length + 5))
    for i, entry in enumerate(entries, 1):
        try:
            print(f"{i}. " + " " * (len(str(len(entries))) - len(str(i))) + f"{entry['service']:<{max_service_length}} {entry['username']:<{max_username_length + 5}}")
        except Exception:
            print(f"{i}. {entry['service']} {entry['username']}")

def exit_application(spm: Optional[SecurePasswordManager]) -> None:
    """
    Log out and clean up sensitive data.

    Args:
        spm: SecurePasswordManager instance to clean up
    """

    logger.info("Application exiting normally")

    pyperclip.copy("")
    # Reset the SecurePasswordManager instance to prevent any leakage of sensitive information.
    if spm is not None:
        spm.key = None
        spm.salt = None
        spm.file_path = ""
        for entry in spm.entries:
            entry["service"] = ""
            entry["username"] = ""
            entry["password"] = ""
        spm.entries = []
    sys.exit(0)


def validate_file(filename: str) -> Optional[str]:
    """
    Validate the file.

    Args:
        filename: Path to file

    Returns:
        Error message if file is not valid, None otherwise
    """

    logger.info(f"Validating file: {filename}")
    absolute_filename = Path(filename).absolute()
    clean_filename = Path(filename).resolve()

    try:
        actual_perm = clean_filename.stat().st_mode & 0o777
        absolute_perm = absolute_filename.stat().st_mode & 0o777
        if actual_perm != 0o600 or absolute_perm != 0o600:
            return f"Incorrect file permissions. Expected 0600, got {oct(actual_perm)}"
        elif clean_filename.is_symlink() or absolute_filename.is_symlink():
            return "File is a symbolic link (not allowed)"
        elif clean_filename.suffix != SUFFIX:
            return f"File does not have the correct suffix. Expected {SUFFIX}, got {clean_filename.suffix}"
    except FileNotFoundError:
        return "File does not exist"

def create_vault(file_path: str) -> Optional[SecurePasswordManager]:
    """
    Create a new vault file.
    
    Args:
        file_path: Path to the vault file
        
    Returns:
        SecurePasswordManager instance or None on error
    """

    logger.info("Starting create new vault file")
    print("Creating new vault file...")

    password, err = dialog_create_master_password()
    if err:
        if err == ERR_OPERATION_CANCELED:
            logger.info(ERR_OPERATION_CANCELED)
        else:
            logger.error(f"{ERR_READING_PASSWORD} {err}")
            print(f"{ERR_READING_PASSWORD} {err}")
        return None

    print("Vault file created successfully!")

    # Generate salt
    salt = os.urandom(32)

    # Derive key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode("utf-8"))

    print("Creating a new Secure Password Manager for you...")

    pm = SecurePasswordManager(key, salt)
    pm.file_path = file_path

    ans, err = dialog_yes_no("Would you like to add sample entries?")
    if err is None and ans:
        pm.add_entry("example.com", "example", password_generator(12, True, True, False))
        print("Sample entry added.")
    else:
        print("No sample entry added.")

    try:
        pm.save_to_file(file_path)
        print("Vault file saved successfully!")
        return pm
    except Exception as e:
        logger.error(f"Error saving vault file: {e}")
        print("Error saving vault file, please try again.")
        return None


def open_vault(file_path: str) -> Optional[SecurePasswordManager]:
    """
    Open vault file and load SecurePasswordManager.

    Args:
        file_path: Path to the vault file

    Returns:
        SecurePasswordManager instance or None on error
    """

    logger.info("Starting open vault process")
    vault_file = Path(file_path)

    exists = vault_file.exists()
    if not exists:
        yes, err = dialog_yes_no("No vault file found. Do you want to create a new vault?")
        if err:
            logger.error(f"Error reading input: {err}")
            return None
        if yes:
            return create_vault(file_path)
        else:
            print("Exiting...")
            return None
    
    password, err = dialog_verify_master_password()
    if err:
        if err == ERR_OPERATION_CANCELED:
            logger.info(ERR_OPERATION_CANCELED)
        else:
            logger.error(f"{ERR_READING_PASSWORD} {err}")
        return None

    # Load the vault file
    try:
        with open(vault_file, "rb") as f:
            file_data = f.read()
    except Exception as e:
        logger.error(f"Error reading vault file {vault_file}: {e}")
        print("Error reading vault file.")
        return None

    salt = file_data[:32]

    # Derive key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode("utf-8"))

    spm = SecurePasswordManager(key, salt)
    spm.file_path = file_path

    # Load the vault file
    try:
        spm.load_data(file_data)
    except Exception as e:
        if "Message decryption failed" in str(e):
            logger.error("Wrong master password")
            print("Wrong master password")
        else:
            logger.error(f"Error loading passwords: {e}")
            print("Oops! Something went wrong. Please try again.")
        return None

    logger.info("Vault opened successfully")
    return spm


def password_generator(
    length: int,
    include_uppercase: bool = False,
    include_numbers: bool = False,
    include_symbols: bool = False,
) -> str:
    """
    Generate a secure random password.

    Args:
        length: Password length (MIN_LENGTH-MAX_LENGTH characters)
        include_uppercase: Include uppercase letters
        include_numbers: Include numbers
        include_symbols: Include symbols

    Returns:
        Generated password string
    """

    if length < MIN_LENGTH or length > MAX_LENGTH:
        raise ValueError(f"password length must be between {MIN_LENGTH} and {MAX_LENGTH} characters")

    charset = LOWERCASE

    if include_uppercase:
        charset += UPPERCASE

    if include_numbers:
        charset += NUMBERS

    if include_symbols:
        charset += SYMBOLS

    password = "".join(secrets.choice(charset) for _ in range(length))
    return password


def sanitize_input(text: str, max_length: int = 255, allow_empty: bool = True) -> Optional[str]:
    """
    Sanitize text input.
    
    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length
        allow_empty: Whether empty strings are allowed
        
    Returns:
        Sanitized text or None if invalid
    """
    if not text:
        return None if not allow_empty else ""
    
    text = text.strip()
    
    # Length check
    if len(text) > max_length:
        return None
    
    # Remove control characters (keep newline and tab for some cases)
    text = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', '', text)
    
    return text if text or allow_empty else None