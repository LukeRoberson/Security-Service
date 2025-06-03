"""
The security service

Used for:
    - Authenticating users with an iDP
    - Encrypting and decrypting data
    - Validating signatures of messages
    - Teams token management
"""

from flask import Flask
from flask_session import Session
import os
import requests
import logging

from azure import azure_auth
from systemlog import system_log
from api import security_api


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

# Register the security API blueprint
app.register_blueprint(security_api)


# Log startup message
system_log.log("The security service is starting")

# Register authentication blueprint
app.register_blueprint(azure_auth)

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
