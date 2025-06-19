"""
Module: main.py

The main entry point for the security service.
This service handles security-related tasks such as:
    - Authenticating web users with an IDP
    - Teams token management
    - Encrypting and decrypting data
    - Validating signatures of messages

Module Tasks:
    - Fetch global configuration from the web interface
    - Set up logging based on the global configuration
    - Create a Flask application
    - Register blueprints for security API and authentication
    - Provide the entry point for the Flask application

Usage:
    This is a Flask application that should run behind a WSGI server inside
        a Docker container.
    Build the Docker image and run it with the provided Dockerfile.

Functions:
    - logging_setup:
        Sets up the root logger for the web service.
    - create_app:
        Creates the Flask application instance and sets up the configuration.

Blueprints:
    - security_api: Handles security-related API endpoints

Dependencies:
    - Flask: For creating the web application
    - Flask-Session: For session management
    - requests: For making API calls to other services
    - logging: For logging messages to the terminal
    - azure_auth: For Azure Active Directory authentication
    - system_log: For sending logs to a logging service
"""

# Standard library imports
from flask import Flask
from flask_session import Session
import os
import logging

# Custom imports
from azure import azure_auth
from api import security_api
from sdk import Config


CONFIG_URL = "http://core:5100/api/config"


def logging_setup(
    config: dict,
) -> None:
    """
    Set up the root logger for the web service.

    Args:
        config (dict): The global configuration dictionary

    Returns:
        None
    """

    # Get the logging level from the configuration (eg, "INFO")
    log_level_str = config['web']['logging-level'].upper()
    log_level = getattr(logging, log_level_str, logging.INFO)

    # Set up the logging configuration
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logging.info("Logging setup complete with level: %s", log_level)


def create_app(
) -> Flask:
    """
    Create the Flask application instance and set up the configuration.
    Registers the necessary blueprints for the web service.

    Args:
        None

    Returns:
        Flask: The Flask application instance.
    """

    # Create the Flask application
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('api_master_pw')
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = '/app/flask_session'
    Session(app)

    # Register blueprints
    app.register_blueprint(security_api)
    app.register_blueprint(azure_auth)

    return app


# Setup the security service
global_config = {}
with Config(CONFIG_URL) as config:
    global_config = config.read()
logging_setup(global_config)
app = create_app()
