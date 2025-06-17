"""
Module: api.py

API endpoints for the security service. Other services can use these endpoints
to authenticate users, generate tokens, and perform cryptographic operations.

Functions:
    - generate_auth_token: Generate a secure token for a user.
        This is used to prove to the caller that the security service has
        responded to the API request, not some attacker.

Classes:
    - PluginAPI: Manage plugins through the Core API.

Blueprint lists routes for the security API. This is registered in main.py

Routes:
    - /api/health:
        Health check endpoint to ensure the service is running.
    - /auth:
        Authenticate users and generate tokens.
    - /api/hash:
        Generate a hash for a given message and verify its signature.
    - /api/crypto:
        Encrypt or decrypt data based on the request type.
    - /api/token:
        Return a bearer token for the Teams user.
        This can also be used to check if the user is authenticated.

Blueprints:
    security_api: Flask blueprint for the security API.

Endpoints:
    - /api/health:
        Health check endpoint to ensure the service is running.
    - /auth:
        Authenticate users and generate tokens.
        Users are redirected here from other services.
    - /api/hash:
        Generate a hash for a given webhook, in order to verify its signature.
    - /api/basic:
        Handle basic authentication for plugins.
    - /api/crypto:
        Encrypt or decrypt a string using AES256 encryption.
    - /api/token:
        Return a bearer token for the Teams user to the caller.
        Retrieves the token from the TokenManager.
    - /api/refresh_token:
        Refresh the Teams user token to ensure it is valid and up-to-date.
        Stores the new token in the TokenManager.

Dependencies:
    - Flask: Web framework for building the API.
    - hmac, hashlib: Libraries for generating secure hashes.
    - itsdangerous: Library for generating secure tokens.
    - requests: Library for making HTTP requests to the Core API.
    - base64: Library for encoding and decoding base64 strings.

Custom Dependencies:
    - CryptoSecret: Custom module for cryptographic operations.
    - azure/login_required: Custom module to add security to the web interface.
    - azure/graph_token_refresh: Custom module to refresh the Teams user token.
    - TokenManager: Custom module for managing tokens.
"""

# Standard library imports
from flask import (
    request,
    session,
    current_app,
    Blueprint,
    Response,
    redirect,
    jsonify,
    make_response
)
import logging
import hmac
import hashlib
from itsdangerous import URLSafeTimedSerializer
from time import time
from typing import Any, cast, Optional
import requests

# Custom module imports
from crypto import CryptoSecret
from azure import login_required, graph_token_refresh
from tokenmgmt import TokenManager
import base64


PLUGINS_URL = "http://core:5100/api/plugins"


class PluginAPI:
    """
    Manage plugins through the Core API.

    Args:
        plugins_url (str): The URL to the plugins API.
    """

    def __init__(
        self,
        plugins_url: str = PLUGINS_URL
    ):
        """
        Initialize the PluginAPI with the URL to the plugins API.
        """
        self.url = plugins_url

    def __enter__(
        self
    ) -> 'PluginAPI':
        """
        Enter the runtime context related to this object.

        Returns:
            PluginAPI: The instance of the PluginAPI.
        """

        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_value: Optional[Exception],
        traceback: Optional[object]
    ) -> None:
        """
        Exit the runtime context related to this object.

        Args:
            exc_type (Optional[type]): The exception type.
            exc_value (Optional[Exception]): The exception value.
            traceback (Optional[object]): The traceback object.
        """

        # No cleanup needed for this context manager
        pass

    def get_plugins(
        self,
    ) -> list[dict]:
        """
        Fetch the list of plugins from the core API.

        Args:
            plugins_url (str): The URL to fetch the plugins from.

        Returns:
            dict: A dictionary containing the list of plugins.
        """

        # API call
        try:
            response = requests.get(
                self.url,
                headers={"X-Plugin-Name": "all"},
                timeout=3
            )
            if response.status_code == 200:
                plugin_list = response.json()['plugins']
                logging.debug("Fetched plugins from API: %s", plugin_list)

            else:
                plugin_list = []
                logging.warning(
                    "Failed to fetch plugins from API:\n %s",
                    response.text
                )

        except Exception as e:
            plugin_list = []
            logging.error("Error accessing the plugins API: %s", e)

        return plugin_list

    def get_plugin_by_name(
        self,
        plugin_name: str
    ) -> Optional[dict]:
        """
        Find a plugin's configuration by its name.

        Args:
            plugin_name (str): The name of the plugin to find.
        """

        plugin_list = self.get_plugins()
        for plugin in plugin_list:
            if plugin['name'] == plugin_name:
                return plugin

        return None


def generate_auth_token(
    user: str,
    secret_key: str,
) -> str:
    """
    Generate a secure token for the user.
    The secret key is used to sign the token.
        It needs to be known to services that verify the token.

    Args:
        user (str): The username or identifier of the user.
        secret_key (str): The secret key used for signing the token.

    Returns:
        str: The generated token.
    """

    # Create a URL-safe serializer with the secret key
    serializer = URLSafeTimedSerializer(secret_key)

    # Generate a token with the user information
    return serializer.dumps({'user': user})


# Create a Flask blueprint for the API
security_api = Blueprint(
    'security_api',
    __name__
)


@security_api.route(
    '/api/health',
    methods=['GET']
)
def health():
    """
    Health check endpoint.
    Returns a JSON response indicating the service is running.
    """

    return jsonify(
        {
            'status': 'ok'
        }
    )


@security_api.route(
    '/auth',
    methods=['GET']
)
@login_required
def auth():
    '''
    Authentication endpoint.

    Users are redirected here from other services.
    The @login_required decorator checks if the user is logged in.
        If not, they are redirected to the login page.

    Generates a token for the user and redirects them
        to the original URL with the token as a query parameter.
    The token is to confirm to the caller that the security service
        has responded to the API request, not some attacker.
    '''

    # Get user details from the session and generate a token
    user = session.get('user')
    if not user:
        logging.error("User not found in session. Redirecting to login.")
        return redirect('/login')

    secret_key = current_app.config['SECRET_KEY']
    token = generate_auth_token(user, secret_key)

    # Redirect to the original URL with the token
    redirect_url = request.args.get('redirect')
    if redirect_url:
        sep = '&' if '?' in redirect_url else '?'
        redirect_with_token = f"{redirect_url}{sep}token={token}"
        return redirect(redirect_with_token)

    # If no redirect URL is provided, return the token as JSON
    return jsonify(
        {
            'token': token,
        }
    )


@security_api.route(
    '/api/hash',
    methods=['POST']
)
def api_hash():
    """
    Endpoint to generate a hash for a given message.
        Used to verify signatures using HMAC with SHA-256.

    Expects a JSON payload with:
        'message' - The message to hash.
        'secret' - The secret key used for hashing.
        'signature' - The expected hash signature to compare against.

    Returns a JSON response indicating success or failure.
    """

    # Get the fields from the request
    data = request.get_json()
    signature = data.get('signature')
    message = data.get('message')
    secret = data.get('secret')

    # Check the required fields are present
    if not message or not secret or not signature:
        logging.error("Missing message, secret, or signature in the request.")
        return jsonify({'error': 'Missing message, secret, or signature'}), 400

    # Generate our own hash
    hash = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()

    # Return a simple success or failure response
    if not hmac.compare_digest(hash, signature):
        return jsonify(
            {
                'result': 'error',
                'error': 'Invalid signature'
            }
        ), 401

    return jsonify(
        {
            'result': 'success'
        }
    )


@security_api.route(
    '/api/basic',
    methods=['POST']
)
def api_basic() -> Response:
    """
    Endpoint to handle basic authentication.

    Expects a JSON payload with:
        'plugin' - The name of the plugin making the request.
        'auth' - The auth string
    """

    data = request.get_json()

    if not data:
        logging.error("No data provided in the request.")
        return make_response(
            jsonify(
                {
                    "result": "error",
                    "error": "No data provided in the request"
                }
            ),
            400
        )

    # Check if the required fields are present
    plugin = data.get('plugin')
    auth = data.get('auth')

    if not plugin or not auth:
        logging.error("Missing 'plugin' or 'auth' in the request.")
        return make_response(
            jsonify(
                {
                    "result": "error",
                    "error": "Missing 'plugin' or 'auth' in the request"
                }
            ),
            400
        )

    # Get the secret for the plugin from the Core API
    with PluginAPI() as plugin_api:
        # Get the plugin configuration from the Core API
        plugin_config = plugin_api.get_plugin_by_name(plugin)
        if not plugin_config:
            logging.error(f"Plugin '{plugin}' not found in the Core API.")
            return make_response(
                jsonify(
                    {
                        "result": "error",
                        "error": f"Plugin '{plugin}' not found"
                    }
                ),
                404
            )

        secret = plugin_config['webhook']['secret']

    # Convert the auth string to username and password
    auth = auth.replace('Basic ', '', 1).strip()
    try:
        decoded_auth = base64.b64decode(auth).decode('utf-8')

    except Exception as e:
        logging.error(f"Failed to decode base64 auth string: {e}")
        return make_response(
            jsonify(
                {
                    "result": "error",
                    "error": "Invalid base64 encoding in 'auth'"
                }
            ),
            400
        )

    # Return a success response
    if decoded_auth == secret:
        return make_response(
            jsonify(
                {
                    "result": "success",
                    "message": f"Authenticated {plugin} successfully"
                }
            ),
            200
        )

    else:
        logging.error(
            f"Authentication failed for plugin '{plugin}'. "
            f"Provided auth: {decoded_auth}, expected: {secret}"
        )
        return make_response(
            jsonify(
                {
                    "result": "error",
                    "error": "Authentication failed"
                }
            ),
            401
        )


@security_api.route(
    '/api/crypto',
    methods=['POST']
)
def api_crypto() -> Response:
    """
    Endpoint to encrypt or decrypt data.

    Expects a 'type' field in the body to indicate the operation
        'encrypt' or 'decrypt'

    For 'encrypt', expects 'plain-text' in the request body.
        This is the string to encrypt.

    For 'decrypt', expects 'encrypted' and 'salt' in the request body.
        This is the encrypted string and the salt used for encryption.

    Returns a JSON response indicating success or failure.
        Includes extra information based on the operation type.
        'encrypted' - The encrypted string
        'salt' - The salt used for encryption
        'decrypted' - The decrypted string
    """

    data = request.get_json()

    # Work out if we're encrypting or decrypting
    crypto_type = data.get('type')
    if crypto_type not in ['encrypt', 'decrypt']:
        logging.error("Invalid crypto type: %s", crypto_type)
        return make_response(
            jsonify(
                {
                    "result": "error",
                    "error": "Invalid crypto type"
                }
            ),
            400
        )

    if crypto_type == 'encrypt':
        # Get the string to encrypt
        plain_text = data.get('plain-text')
        if not plain_text:
            logging.error("Missing 'plain-text' in the request.")
            return make_response(
                jsonify(
                    {
                        "result": "error",
                        "error": "Missing 'plain-text' in the request"
                    }
                ),
                400
            )

        # Encrypt the string using the Crypto class
        with CryptoSecret() as crypto:
            encrypted, salt = crypto.encrypt(plain_text)

        # Return the encrypted string and salt
        return make_response(
            jsonify(
                {
                    "result": "success",
                    "encrypted": str(encrypted),
                    "salt": str(salt)
                }
            ),
            200
        )

    elif crypto_type == 'decrypt':
        # Get the encrypted string and salt
        encrypted = data.get('encrypted')
        salt = data.get('salt')
        if not encrypted or not salt:
            logging.error("Missing 'encrypted' or 'salt' in the request.")
            return make_response(
                jsonify(
                    {
                        "result": "error",
                        "error": "Missing 'encrypted' or 'salt' in the request"
                    }
                ),
                400
            )

        # Decrypt the string using the Crypto class
        with CryptoSecret() as crypto:
            decrypted = crypto.decrypt(encrypted, salt)

        if not decrypted:
            logging.error("Decryption failed.")
            return make_response(
                jsonify(
                    {
                        "result": "error",
                        "error": "Decryption failed"
                    }
                ),
                500
            )

        # Return the decrypted string
        return make_response(
            jsonify(
                {
                    "result": "success",
                    "decrypted": decrypted
                }
            ),
            200
        )

    return make_response(
        jsonify(
            {
                "result": "error",
                "error": "Invalid crypto type"
            }
        ),
        400
    )


@security_api.route(
    '/api/token',
    methods=['GET']
)
def bearer_token():
    """
    Endpoint to return a bearer token for the Teams user.
    This is used for authentication with MS Graph API.

    Returns a JSON response with the token, if available.
    If the token is not available, it returns an error.
        - result: 'success' or 'error'
        - token: The bearer token if available
        - validity: The validity time of the token (epoch time)
        - error: Error message if the token is not available

    This endpoint is used to check if the user is authenticated
        200 - Token found
        404 - Token not found
    """

    with TokenManager() as token_manager:
        # Check if the token is available
        service_account = current_app.config['GLOBAL_CONFIG']['teams']['user']
        token = token_manager.get_token(user_id=service_account)
        token = cast(dict[str, Any], token)

    # Token found
    if token:
        logging.info(
            "/api/token: Returning token for service account: %s",
            service_account
        )

        return make_response(
            jsonify(
                {
                    "result": "success",
                    "user": token['user_id'],
                    "token": token['bearer'],
                    "validity": int(time()) + 60
                }
            ),
            200
        )

    # Token not found
    else:
        logging.warning(
            "/api/token: No token available for service account: %s",
            service_account
        )
        return jsonify(
            {
                'result': 'error',
                'error': f'There is no token available for {service_account}. '
                f'They are likely not authenticated yet.',
            }
        ), 404


@security_api.route(
    '/api/refresh_token',
    methods=['GET']
)
def refresh_token():
    """
    Endpoint to refresh the Teams user token.
    This is used to ensure the token is valid and up-to-date.

    Returns a JSON response indicating success or failure.
        - result: 'success' or 'error'
        - error: Success message or error details
    """

    logging.info("/api/refresh_token: Refreshing Teams user token")
    result = graph_token_refresh()

    print("debug: result", result)

    if result['result'] == 'success':
        logging.info("/api/refresh_token: Token refreshed successfully")
        return jsonify(
            {
                'result': 'success'
            }
        )

    else:
        logging.error(
            "/api/refresh_token: Failed to refresh token"
        )
        return jsonify(
            {
                'result': 'error',
                'error': result.get('error', 'Unknown error occurred')
            }
        )


if __name__ == '__main__':
    print("This module is not designed to be run as a script")
    print("Please import it into another module")
