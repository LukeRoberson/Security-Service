"""
Module: tokenmgmt.py

Manages tokens used to access external services, such as APIs.

When a user logs into the web UI, they are authenticated with Azure,
    which returns a bearer token. This is managed by this module.
The Teams service account also has a bearer token and a refresh token,
    which are also managed by this module.

Classes:
    TokenManager
        Manages external tokens, such as bearer tokens and refresh tokens.
        Provides methods to add, retrieve, and delete tokens.
        Uses an SQLite database to store tokens. When running as a container,
            this lives for the lifetime of the container only.
        Supports context management for automatic database connection handling.

Dependencies:
    sqlite3: Manage an SQLite database for token storage and retrieval.

Custom Dependencies:
    sdk: SystemLog for logging system events.
"""

# Standard library imports
import sqlite3
from typing import Optional, Any
import logging
import time

# Custom imports
from sdk import SystemLog


LOG_URL = "http://logging:5100/api/log"


# Initialize the SystemLog with default values
system_log = SystemLog(
    logging_url=LOG_URL,
    source="security",
    destination=["web"],
    group="service",
    category="security",
    alert="system",
    severity="info"
)


class TokenManager:
    """
    Manages external tokens such as bearer and refresh tokens for Teams
        and other services.

    Tokens are stored in an SQLite database. Supports context management
        for automatic database connection handling.

    Attributes:
        db_path (str): Path to the SQLite database file.
        conn (sqlite3.Connection): SQLite database connection.
        c (sqlite3.Cursor): SQLite database cursor for executing queries.
    """

    def __init__(
        self,
        db_path: str = "tokens.db",
    ) -> None:
        """
        Initialize the TokenManager

        Args:
            db_path (str): Path to the SQLite database file.
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
        Closes the cursor and connection, optionally rolling back if there
            was an exception.

        Args:
            exc_type (Exception): The type of exception raised, if any.
            exc_val (Exception): The value of the exception raised, if any.
            exc_tb (traceback): The traceback of the exception raised, if any.
        """

        # commit only if there's no exception
        if exc_type is None:
            if self.conn is not None:
                self.conn.commit()

        # rollback if an error occurred
        else:
            if self.conn is not None:
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

        if self.c is None:
            raise RuntimeError("Database cursor is not initialized")
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
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")
        self.conn.commit()

        logging.info("Database initialized at %s", self.db_path)

    def _clean_db(
        self
    ) -> None:
        """
        Check database for expired tokens, and remove them.
        The expiry field is a UNIX timestamp (epoch)
        """

        current_time = int(time.time())
        if self.c is None:
            raise RuntimeError("Database cursor is not initialized")
        self.c.execute(
            """
            DELETE FROM tokenmgmt
            WHERE expiry IS NOT NULL AND expiry < ?
            """,
            (current_time,)
        )
        if self.conn is None:
            raise RuntimeError("Database connection is not initialized")
        self.conn.commit()

        logging.info("Cleaned up expired tokens from the database")

    def add_token(
        self,
        user_id: Optional[str] = None,
        bearer_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        expiration: Optional[int] = None,
    ) -> bool:
        """
        Add a new token to the database.

        Args:
            user_id (str, optional): The user ID associated with the token.
            bearer_token (str): The bearer token to be stored.
            refresh_token (str, optional): The refresh token to be stored.
            expiration (int, optional): The expiration time of the token.

        Returns:
            bool: True if the token was added successfully, False otherwise.

        Raises:
            ValueError: If any of the required parameters are missing
                or invalid.
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
            if self.c is None:
                raise RuntimeError("Database cursor is not initialized")
            self.c.execute(
                """
                INSERT INTO tokenmgmt (user_id, bearer, refresh, expiry)
                VALUES (?, ?, ?, ?)
                """,
                (user_id, bearer_token, refresh_token, expiration)
            )

            logging.info("Token added for user_id: %s", user_id)

        except Exception as e:
            logging.error("Failed to add token: %s", e)
            system_log.log(
                f"Failed to add token: {e}",
                severity="error",
            )
            return False

        # Schedule a refresh job
        return True

    def get_token(
        self,
        user_id: Optional[str] = None,
    ) -> list[dict[str, Any]] | dict | None:
        """
        Get a token from the database.

        Args:
            user_id (str, optional): The user ID associated with the token.
                If not provided, all tokens are returned.

        Returns:
            dict | None:
                A dictionary containing the token information,
                or None if no token is found.
                - 'user_id': The user ID associated with the token,
                - 'bearer': The bearer token,
                - 'refresh': The refresh token (if available),
                - 'expiry': The expiration time of the token (epoch).
        """

        # Clean the database before retrieving tokens
        self._clean_db()

        # if there is no user_id provided, return all tokens
        if not user_id:
            if self.c is None:
                raise RuntimeError("Database cursor is not initialized")
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
            if self.c is None:
                raise RuntimeError("Database cursor is not initialized")
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

        Args:
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
            if self.c is None:
                raise RuntimeError("Database cursor is not initialized")
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
                severity="error",
            )
            return False


if __name__ == '__main__':
    print("This module is not designed to be run as a script")
    print("Please import it into another module")
