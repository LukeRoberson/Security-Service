'''
Provides encryption and decryption for device secrets
Uses the master password stored in an environment variable (api_master_pw)

Classes:
    CryptoSecret
        Provides encryption and decryption for device secrets
'''

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

import base64
import os
import logging

import traceback
from typing import Tuple


class CryptoSecret:
    '''
    Provides encryption and decryption for device secrets

    Supports being instantiated with the 'with' statement

    Methods:
        __init__()
            Class constructor

        __enter__()
            Context manager

        __exit__(exc_type, exc_value, exc_traceback)
            Context manager

        decrypt(secret, salt)
            Decrypt a secret using AES256 encryption

        encrypt(password)
            Encrypt a password using AES256 encryption

        _build_key(salt)
            Build a key using the master password and a salt
    '''

    def __init__(
        self
    ) -> None:
        '''
        Class constructor
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
    ) -> object:
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
        exc_traceback: traceback,
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
                f"Exception of type {exc_type.__name__} occurred: {exc_value}"
            )
            if exc_traceback:
                print("Traceback:")
                print(traceback.format_tb(exc_traceback))

    def decrypt(
        self,
        secret: str,
        salt: str,
    ) -> str | bool:
        '''
        Uses a salt and the master password to decrypt the secret (password)
        The master password is stored in an environment variable

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
        encrypted_message = fernet.encrypt(password.encode())

        # Encode salt as base64 string for safe transport
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        encrypted_str = encrypted_message.decode('utf-8')  # Also decode encrypted_message for JSON

        return encrypted_str, salt_b64

    def _build_key(
        self,
        salt: str,
    ) -> Fernet:
        '''
        Builds a key using the master password and a salt

        Parameters:
            salt : str
                The salt used to encrypt the password

        Returns:
            fernet : Fernet
                The Fernet object used to encrypt/decrypt the password
        '''

        # generate a key using PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master.encode()))

        # create a Fernet object using the key
        fernet = Fernet(key)

        return fernet


if __name__ == '__main__':
    print("This module is not designed to be run as a script")
    print("Please import it into another module")
