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

from flask import Flask
import flask
from flask_session import Session
import os
import requests
from colorama import Fore, Style
from datetime import datetime

from azure import azure_auth, login_required


# Log startup message
print(
    Fore.GREEN,
    "Starting security service...",
    Style.RESET_ALL
)

requests.post(
    "http://web-interface:5100/api/webhook",
    json={
        "source": "security service",
        "type": "service.startup",
        "timestamp": str(datetime.now()),
        "message": "The security service is starting",
    },
)

# Get global config
global_config = None
try:
    response = requests.get("http://web-interface:5100/api/config")
    response.raise_for_status()  # Raise an error for bad responses
    global_config = response.json()

except Exception as e:
    print(
        Fore.RED,
        "Failed to fetch global config from web interface.",
        e,
        Style.RESET_ALL
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


@app.route('/test')
@login_required
def test():
    return flask.jsonify(
        {
            'result': 'This is the test page'
        }
    )


@app.route('/api/auth')
def api_auth():
    return flask.jsonify(
        {
            'result': 'success'
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
print(
    Fore.GREEN,
    "Security service has started...",
    Style.RESET_ALL
)

requests.post(
    "http://web-interface:5100/api/webhook",
    json={
        "source": "security service",
        "type": "service.startup",
        "timestamp": str(datetime.now()),
        "message": "The security service has started",
    },
)


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
