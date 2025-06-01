"""
Token management module.
Contains classes and functions for managing tokens,
"""


import sqlite3
from typing import Optional
import logging

from systemlog import system_log
import time


class TokenManager:
    '''
    TokenManager class.
        This class is responsible for managing external tokens,
        such as bearer tokens and refresh tokens for teams.

    Use the context manager when using this class to ensure
        that the database connection is properly closed.

    Tokens are stored in an SQLite database, which is created
        at runtime, and destroyed at the end of the container's life.

    Tokens can be added, retrieved, and deleted.
        To update a token, it must be deleted and added again.

    Methods:
        - __init__: Initialize the TokenManager with a database path.
        - __repr__: Unambiguous string representation of this instance.
        - __str__: User-friendly representation of this instance.
        - __iter__: Iterate over tokens stored in the database.
        - __enter__: Open the database connection and return self.
        - __exit__: Close the database connection, committing or rolling back
        - _create_db: Create the SQLite database for token management.
        - _clean_db: Check database for expired tokens, and remove them.
        - add_token: Add a new token to the database.
        - get_token: Get a token from the database.
        - delete_token: Delete a token from the database based on user ID.
    '''

    def __init__(
        self,
        db_path: str = "tokens.db",
    ) -> None:
        """
        Initialize the TokenManager

        Parameters:
            db_path (str): Path to the SQLite database file.
                Defaults to "tokens.db".
        """

        # Setup database connection
        self.db_path = db_path
        self.conn = None
        self.c = None

    def __repr__(
        self
    ) -> str:
        """
        Unambiguous string representation of this instance.
        """

        return f"<TokenManager db_path='{self.db_path}'>"

    def __str__(
        self
    ) -> str:
        """
        User-friendly representation of this instance.

        Returns:
            str: A string representation of the TokenManager instance.
        """

        return f"TokenManager for DB at {self.db_path}"

    def __iter__(
        self
    ) -> iter:
        """
        Make this class iterable over tokens stored in the database.
        """

        tokens = self.get_token()
        for token in tokens:
            yield token

    def __enter__(
        self
    ) -> "TokenManager":
        """
        Called when entering the 'with' block.
        Opens the database connection and returns self.

        Returns:
            TokenManager: The instance of the TokenManager class.
        """

        # Connect to the SQLite database
        self.conn = sqlite3.connect(self.db_path)
        self.c = self.conn.cursor()
        self._create_db()

        return self

    def __exit__(
        self,
        exc_type,
        exc_val,
        exc_tb
    ) -> None:
        """
        Called when exiting the 'with' block.
        Closes the cursor and connection, optionally rolling back if there
            was an exception.
        """

        # commit only if there's no exception
        if exc_type is None:
            self.conn.commit()

        # rollback if an error occurred
        else:
            self.conn.rollback()

        # Close the cursor and connection
        if self.c:
            self.c.close()
        if self.conn:
            self.conn.close()

    def _create_db(
        self
    ) -> None:
        """
        Create the SQLite database for token management.
            This is called when the TokenManager is initialized.

        Required fields:
            - user_id: The user ID associated with the token.
            - bearer: The bearer token to be stored.
            - expiry: The expiration time of the token in epoch format.

        Optional fields:
            - refresh: The refresh token to be stored.
        """

        self.c.execute("""
            CREATE TABLE IF NOT EXISTS tokenmgmt (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT NOT NULL,
                bearer TEXT NOT NULL,
                refresh TEXT NULL,
                expiry INTEGER NOT NULL
            )
        """)
        self.conn.commit()

        logging.info("Database initialized at %s", self.db_path)
        system_log.log("Logging database initialized")

    def _clean_db(
        self
    ) -> None:
        """
        Check database for expired tokens, and remove them.
        The expiry field is a UNIX timestamp (epoch)
        """

        current_time = int(time.time())
        self.c.execute(
            """
            DELETE FROM tokenmgmt
            WHERE expiry IS NOT NULL AND expiry < ?
            """,
            (current_time,)
        )
        self.conn.commit()

        logging.info("Cleaned up expired tokens from the database")

    def add_token(
        self,
        user_id: str = None,
        bearer_token: str = None,
        refresh_token: str = None,
        expiration: int = None,
    ) -> bool:
        """
        Add a new token to the database.
            Requires a bearer token, and optionally a refresh token
            An expiry time must be provided

        Parameters:
            user_id (str, optional): The user ID associated with the token.
            bearer_token (str): The bearer token to be stored.
            refresh_token (str, optional): The refresh token to be stored.
            expiration (int, optional): The expiration time of the token.

        Returns:
            bool: True if the token was added successfully, False otherwise.
        """

        # Validate input parameters
        if not user_id or not bearer_token or not expiration:
            logging.error("Add Token: Missing required parameters")
            return False

        if type(expiration) is not int:
            logging.error("Add Token: Expiration must be an integer (epoch)")
            return False

        if expiration < int(time.time()):
            logging.error("Add Token: Expiration time must be in the future")
            return False

        # Clean the database before adding a new token
        self._clean_db()

        try:
            self.c.execute(
                """
                INSERT INTO tokenmgmt (user_id, bearer, refresh, expiry)
                VALUES (?, ?, ?, ?)
                """,
                (user_id, bearer_token, refresh_token, expiration)
            )

            logging.info("Token added for user_id: %s", user_id)
            return True

        except Exception as e:
            logging.error("Failed to add token: %s", e)
            system_log.log(
                f"Failed to add token: {e}",
                secerity="error",
            )
            return False

    def get_token(
        self,
        user_id: Optional[str] = None,
    ) -> dict | None:
        """
        Get a token from the database.

        Parameters:
            user_id (str, optional): The user ID associated with the token.
                If not provided, all tokens are returned.

        Returns:
            dict | None:
                A dictionary containing the token information,
                or None if no token is found.
        """

        # Clean the database before retrieving tokens
        self._clean_db()

        # if there is no user_id provided, return all tokens
        if not user_id:
            self.c.execute(
                """
                SELECT user_id, bearer, refresh, expiry
                FROM tokenmgmt
                """
            )
            rows = self.c.fetchall()
            if rows:
                return [
                    {
                        "user_id": row[0],
                        "bearer": row[1],
                        "refresh": row[2],
                        "expiry": row[3],
                    }
                    for row in rows
                ]

        # if a user_id is provided, return the token for that user_id
        else:
            self.c.execute(
                """
                SELECT user_id, bearer, refresh, expiry
                FROM tokenmgmt
                WHERE user_id = ?
                """,
                (user_id,)
            )
            row = self.c.fetchone()
            if row:
                return {
                    "user_id": row[0],
                    "bearer": row[1],
                    "refresh": row[2],
                    "expiry": row[3],
                }

        return None

    def delete_token(
        self,
        user_id: str,
    ) -> bool:
        """
        Delete a token from the database, based on the user ID.

        Parameters:
            user_id (str): The user ID associated with the token to be deleted.

        Returns:
            bool: True if the token was deleted successfully, False otherwise.
        """

        # Validate input parameters
        if not user_id:
            logging.error("Delete Token: Missing user_id parameter")
            return False

        # Delete the token for the given user_id
        try:
            self.c.execute(
                """
                DELETE FROM tokenmgmt
                WHERE user_id = ?
                """,
                (user_id,)
            )

            # Check if the token was deleted
            if self.c.rowcount > 0:
                logging.info("Token deleted for user_id: %s", user_id)
                return True
            else:
                logging.warning("No token found for user_id: %s", user_id)
                return False

        except Exception as e:
            logging.error("Failed to delete token: %s", e)
            system_log.log(
                f"Failed to delete token: {e}",
                secerity="error",
            )
            return False
