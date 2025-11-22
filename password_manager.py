"""Secure Password Manager with CRUD operations and encryption/decryption capabilities."""

import os
import sys
import secrets
import string
import hashlib
import hmac
import json
import logging

from pathlib import Path
from typing import List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
NUMBERS = "0123456789"
SYMBOLS = "!@#$%^&*()_+[]{}|;:,.<>?/~`"

MIN_LENGTH = 8
MAX_LENGTH = 64

class SecurePasswordManager:
    """Manages password entries with AES-256-GCM encryption and HMAC-SHA256 authentication."""

    def __init__(self, key: bytes, salt: bytes):
        """
        Initialize SecurePasswordManager.

        Args:
            key: 32-byte key for AES-256 encryption
            salt: Salt bytes for key derivation
        """

        logger.info("Creating new SecurePasswordManager instance")
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256 encryption")

        self.key = key
        self.hash_key = self.derive_hash_key(key)
        self.salt = salt
        self.entries: List[dict] = []
        self.file_path = ""  # Path to the database file

    def derive_hash_key(self, key: bytes) -> bytes:
        """
        Derive HMAC key from encryption key using SHA-256.

        Args:
            key: Encryption key

        Returns:
            HMAC key
        """

        logger.info("HMAC key derived from encryption key")
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key)
        return digest.finalize()

    def generate_hmac(self, data: bytes) -> bytes:
        """
        Generate HMAC-SHA256 for data integrity verification.

        Args:
            data: Data to generate HMAC for

        Returns:
            HMAC bytes
        """

        return hmac.new(self.hash_key, data, hashlib.sha256).digest()

    def verify_hmac(self, data: bytes, hash_bytes: bytes) -> bool:
        """
        Verify HMAC-SHA256 for data integrity.
        
        Args:
            data: Data to verify HMAC for
            hash_bytes: HMAC bytes to verify

        Returns:
            True if HMAC is valid, False otherwise
        """

        expected_hash = self.generate_hmac(data)
        return hmac.compare_digest(expected_hash, hash_bytes)

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data using AES-256-GCM with HMAC authentication.

        Args:
            data: Plaintext data to encrypt

        Returns:
            Encrypted data with nonce prepended
        """

        logger.info("Encrypting data")
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)  # 12 bytes for GCM nonce

        hmac_bytes = self.generate_hmac(data)
        data_with_hmac = hmac_bytes + data

        ciphertext = aesgcm.encrypt(nonce, data_with_hmac, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM and verify HMAC.

        Args:
            data: Encrypted data with nonce prepended

        Returns:
            Decrypted plaintext data

        Raises:
            ValueError: If decryption or HMAC verification fails
        """

        logger.info("Decrypting data")
        if len(data) < 12:
            raise ValueError("Ciphertext too short")

        nonce = data[:12]
        ciphertext = data[12:]

        aesgcm = AESGCM(self.key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise ValueError("Message decryption failed") from e

        hmac_size = 32  # SHA-256 digest size
        if len(plaintext) < hmac_size:
            raise ValueError("Data too short")

        hmac_bytes = plaintext[:hmac_size]
        data_bytes = plaintext[hmac_size:]

        if not self.verify_hmac(data_bytes, hmac_bytes):
            raise ValueError("Data integrity check failed")

        return data_bytes

    def add_entry(self, service: str, username: str, password: str) -> None:
        """
        Add a new entry to the password manager.

        Args:
            service: Service name
            username: Username for the service
            password: Password for the service
        """

        logger.info(f"Adding entry for service: {service}")
        self.entries.append({"service": service, "username": username, "password": password})

    def save_to_file(self, filename: str) -> None:
        """
        Save encrypted entries to file.

        Args:
            filename: Path to the file to save to

        Raises:
            IOError: If file operations fail
            ValueError: If encryption fails
        """
        
        logger.info(f"Saving entries to file: {filename}")
        data = json.dumps(
            [{"service": e["service"], "username": e["username"], "password": e["password"]} for e in self.entries],
            indent=None,
        ).encode("utf-8")

        encrypted_data = self.encrypt(data)

        # Prepend the salt to the encrypted data
        data_to_save = self.salt + encrypted_data

        clean_filename = Path(filename).absolute()
        swap_filename = str(clean_filename) + "." + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
        fd = os.open(swap_filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        logger.info(f"Writing swap file: {swap_filename}")

        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data_to_save)
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            # If there's an error, close the file descriptor
            os.close(fd)
            logger.error(f"Error writing swap file: {swap_filename}, closing file descriptor: {fd}")
            raise e

        if clean_filename.exists():
            os.unlink(str(clean_filename))
            logger.debug(f"Cleaned up final file: {clean_filename}")

        # Rename the swap file to the final file
        try:
            os.replace(swap_filename, str(clean_filename))
            logger.debug(f"Swap file {swap_filename} renamed to {clean_filename}")
        except Exception:
            logger.error(f"Error renaming swap file: {swap_filename}")
            raise

        # Set permissions on the final file to be sure it's correct
        try:
            os.chmod(str(clean_filename), 0o600)
            logger.debug(f"Set permissions on final file {clean_filename} to 0600")
        except Exception:
            logger.error(f"Error setting permissions on final file: {clean_filename}")
            raise


    def load_data(self, data: bytes) -> None:
        """
        Load encrypted entries from data bytes.

        Args:
            data: Encrypted data bytes with salt prepended

        Raises:
            IOError: If file operations fail
            ValueError: If decryption fails
        """

        logger.info("Loading SecurePasswordManager from data")

        if len(data) < 32+12:
            raise ValueError("Data too short")

        self.salt = data[:32]
        encrypted_data = data[32:]

        decrypted_data = self.decrypt(encrypted_data)

        entries_data = json.loads(decrypted_data.decode("utf-8"))
        self.entries = [
            {"service": e.get("service", e.get("platform", "")), "username": e["username"], "password": e["password"]}
            for e in entries_data
        ]

