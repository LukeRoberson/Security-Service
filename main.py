"""
The security service

Used for:
    - Authenticating users with an iDP
    - Encrypting and decrypting data

Functions:
    - send_log: Send a log message to the logging service
    - generate_auth_token: Generate a secure token for a user

Endpoints:
    - /auth: Authenticate users and generate tokens
    - /api/hash: Generate a hash for a given message and verify its signature
    - /api/health: Health check endpoint to ensure the service is running
"""

from flask import Flask, session, request, redirect, jsonify
from flask_session import Session
import os
import requests
from itsdangerous import URLSafeTimedSerializer
import logging
import hmac
import hashlib

from azure import azure_auth, login_required
from systemlog import system_log
from crypto import CryptoSecret


# Get global config
global_config = None
try:
    response = requests.get("http://web-interface:5100/api/config", timeout=3)
    response.raise_for_status()  # Raise an error for bad responses
    global_config = response.json()

except Exception as e:
    logging.critical(
        "Failed to fetch global config from web interface."
        f" Error: {e}"
    )

if global_config is None:
    raise RuntimeError("Could not load global config from web interface")

# Set up logging
log_level_str = global_config['config']['web']['logging-level'].upper()
log_level = getattr(logging, log_level_str, logging.INFO)
logging.basicConfig(level=log_level)
logging.info("Logging level set to: %s", log_level_str)

# Create the Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('api_master_pw')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['GLOBAL_CONFIG'] = global_config['config']
Session(app)


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


# Log startup message
system_log.log("The security service is starting")

# Register authentication blueprint
app.register_blueprint(azure_auth)


@app.route('/api/health')
def health():
    """
    Health check endpoint.
    Returns a JSON response indicating the service is running.
    """

    return jsonify({'status': 'ok'})


@app.route('/auth')
@login_required
def auth():
    '''
    Authentication endpoint.
    Users are redirected here from other services.
    The @login_required decorator checks if the user is logged in.
        If not, they are redirected to the login page.
    '''

    # Get user details from the session and generate a token
    user = session.get('user')
    secret_key = app.config['SECRET_KEY']
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


@app.route(
    '/api/hash',
    methods=['POST']
)
def api_hash():
    """
    Endpoint to generate a hash for a given message.

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
        ), 403

    return jsonify(
        {
            'result': 'success'
        }
    )


@app.route(
    '/api/crypto',
    methods=['POST']
)
def api_crypto():
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
        return jsonify(
            {
                'result': 'error',
                'error': 'Invalid crypto type'
            }
        ), 400

    if crypto_type == 'encrypt':
        # Get the string to encrypt
        plain_text = data.get('plain-text')
        if not plain_text:
            logging.error("Missing 'plain-text' in the request.")
            return jsonify(
                {
                    'result': 'error',
                    'error': "Missing 'plain-text' in the request"
                }
            ), 400

        # Encrypt the string using the Crypto class
        with CryptoSecret() as crypto:
            encrypted, salt = crypto.encrypt(plain_text)

        # Return the encrypted string and salt
        return jsonify(
            {
                'result': 'success',
                'encrypted': str(encrypted),
                'salt': str(salt)
            }
        )

    elif crypto_type == 'decrypt':
        # Get the encrypted string and salt
        encrypted = data.get('encrypted')
        salt = data.get('salt')
        if not encrypted or not salt:
            logging.error("Missing 'encrypted' or 'salt' in the request.")
            return jsonify(
                {
                    'result': 'error',
                    'error': "Missing 'encrypted' or 'salt' in the request"
                }
            ), 400

        # Decrypt the string using the Crypto class
        with CryptoSecret() as crypto:
            decrypted = crypto.decrypt(encrypted, salt)

        if not decrypted:
            logging.error("Decryption failed.")
            return jsonify(
                {
                    'result': 'error',
                    'error': 'Decryption failed'
                }
            ), 500

        # Return the decrypted string
        return jsonify(
            {
                'result': 'success',
                'decrypted': decrypted
            }
        )


# Log 'started' message
system_log.log("The security service has started")


'''
NOTE: When running in a container, the host and port are set in the
    uWSGI config. uWSGI starts the process, which means the
    Flask app is not run directly.
    This can be uncommented for local testing.
'''
# if __name__ == "__main__":
#     # Run the application
#     app.run(
#         debug=True,
#         host='0.0.0.0',
#         port=5000,
#     )
