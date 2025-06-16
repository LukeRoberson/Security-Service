'''
Module: crypto.py

Provides encryption and decryption services. This is commonly used for
    passwords and secrets that need to be stored securely.
Plain text strings are encrypted using AES256 encryption. This yields an
    encrypted string and a salt.
An encrypted string can be decrypted to a plain-text string
    (requires corresponding salt).

Requires a master password to be set in the 'api_master_pw'
    environment variable. If this changes, encrypted secrets
    will not be decryptable.
The master password can be set within the OS itself, or passed in through
    Docker. It should never be hard-coded or included in a dockerfile.

Classes:
    CryptoSecret
        Provides encryption and decryption for strings
        Intended to be used with a context manager ('with' statement)

Dependencies:
    cryptography: For encryption and decryption
'''

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

import base64
import os
import logging

import traceback
from typing import Tuple
import types


class CryptoSecret:
    '''
    Encryption and decryption for device secrets

    Supports context manager usage with 'with' statement
    '''

    def __init__(
        self
    ) -> None:
        '''
        Gets the master password from an environment variable
        '''

        # Get master PW from env variable
        self.master = os.getenv('api_master_pw')
        if self.master is None:
            logging.critical(
                "The master password is not set in the environment"
            )

    def __enter__(
        self
    ) -> 'CryptoSecret':
        '''
        Context manager
            Called when the 'with' statement is used

        Returns:
            self
                The instantiated object
        '''

        return self

    def __exit__(
        self,
        exc_type: Exception,
        exc_value: Exception,
        exc_traceback: types.TracebackType,
    ) -> None:
        '''
        Context manager
            Called when the 'with' statement is finished

        Args:
            exc_type : Exception
                The type of exception raised
            exc_value : Exception
                The value of the exception raised
            exc_traceback : traceback
                The traceback of the exception raised
        '''

        # handle errors that were raised
        if exc_type:
            logging.error(
                f"Exception of type {exc_type} occurred: {exc_value}"
            )
            if exc_traceback:
                print("Traceback:")
                print(traceback.format_tb(exc_traceback))

    def _build_key(
        self,
        salt: bytes,
    ) -> Fernet | None:
        '''
        Builds a key using the master password and a salt

        Args:
            salt : str
                The salt that was used to encrypt the password

        Returns:
            fernet : Fernet
                The Fernet object used to encrypt/decrypt the password
            None : If there was a problem creating the key
        '''

        # generate a key using PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        if self.master is None:
            logging.error("Master password is not set, cannot create key")
            return None

        key = base64.urlsafe_b64encode(
            kdf.derive(
                self.master.encode()
            )
        )

        # create a Fernet object using the key
        fernet = Fernet(key)

        return fernet

    def decrypt(
        self,
        secret: str,
        salt: str,
    ) -> str | bool:
        '''
        Uses a salt and the master password to decrypt the string

        Args:
            secret : str
                The secret (encrypted password)
            salt : str
                The salt used to encrypt the password

        Returns:
            password : str
                The decrypted password
            False : boolean
                If there was a problem decrypting the password
        '''

        # Decode the salt from base64
        salt_bytes = base64.b64decode(salt)
        fernet = self._build_key(salt_bytes)

        # decrypt the encrypted message using the same key
        try:
            if fernet is None:
                logging.error("Failed to create Fernet object, cannot decrypt")
                return False
            password = fernet.decrypt(
                secret.encode()
            ).decode('utf-8')

        except Exception as err:
            logging.error("Unable to decrypt the password: %s", err)
            return False

        # Return decrypted password
        return password

    def encrypt(
        self,
        password: str,
        master_pw=None,
    ) -> Tuple[str, str]:
        '''
        Encrypts a password using AES256 encryption

        Args:
            password : str
                The password to encrypt
            master_pw : str
                The master password to use for encryption
                Normally this comes from an environment variable
                However, a specific master password can be passed in

        Returns:
            encrypted_message : str
                The encrypted password
            salt : str
                The salt used to encrypt the password
        '''

        # Override the master password if one is passed in
        if master_pw is not None:
            self.master = master_pw

        # Define a salt and generate a key
        salt = os.urandom(16)
        fernet = self._build_key(salt)

        # encrypt the plaintext using AES256 encryption
        if fernet is None:
            logging.error("Failed to create Fernet object, cannot encrypt")
            return "", ""
        encrypted_message = fernet.encrypt(password.encode())

        # Encode salt as base64 string for safe transport
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        encrypted_str = encrypted_message.decode('utf-8')

        return encrypted_str, salt_b64


if __name__ == '__main__':
    print("This module is not designed to be run as a script")
    print("Please import it into another module")
