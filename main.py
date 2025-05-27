"""
The security service

Used for:
    - Authenticating users with an iDP
    - Encrypting and decrypting data

Usage:
    Run this module to start the security service.

Example:
    $ python main.py
"""

from flask import Flask, session
import flask
from flask_session import Session
import os
import requests
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer
import logging

from azure import azure_auth, login_required


# Logging level can be set to DEBUG, INFO, WARNING, ERROR, or CRITICAL
LOGGING_LEVEL = "INFO"


def send_startup_webhook(
    message: str
) -> None:
    """
    Send a startup message to the web interface.

    Args:
        message (str): The message to send.
    """

    # Terminal log
    logging.info(message)

    # Send a log as a webhook to the logging service
    try:
        requests.post(
            "http://logging:5100/api/log",
            json={
                "source": "security service",
                "destination": ["web"],
                "log": {
                    "type": "service.startup",
                    "timestamp": str(datetime.now()),
                    "message": message
                }
            },
            timeout=3
        )
    except Exception as e:
        logging.warning(
            "Failed to send startup webhook to logging service."
            f" Error: {e}"
        )


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
send_startup_webhook("The security service is starting")

# Get global config
logging.basicConfig(level=logging.INFO)
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


# Create the Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('api_master_pw')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['GLOBAL_CONFIG'] = global_config['config']
Session(app)

# Register authentication blueprint
app.register_blueprint(azure_auth)


@app.route('/api/health')
def health():
    """
    Health check endpoint.
    Returns a JSON response indicating the service is running.
    """

    return flask.jsonify({'status': 'ok'})


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
    redirect_url = flask.request.args.get('redirect')
    if redirect_url:
        sep = '&' if '?' in redirect_url else '?'
        redirect_with_token = f"{redirect_url}{sep}token={token}"
        return flask.redirect(redirect_with_token)

    # If no redirect URL is provided, return the token as JSON
    return flask.jsonify(
        {
            'token': token,
        }
    )


@app.route('/api/crypto')
def api_crypto():
    return flask.jsonify(
        {
            'result': 'success'
        }
    )


# Log 'started' message
send_startup_webhook("The security service has started")


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
