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


CONFIG_URL = "http://core:5100/api/config"


def logging_setup(
    log_level: str = "INFO",
) -> None:
    """
    Set up the root logger for the web service.
    Unlike other services, the logging level can't be retrieved from the
        global configuration. This is because the core service relies on the
        security service to decrypt secrets in the configuration.

    Args:
        logging (str): The logging level to set for the root logger.

    Returns:
        None
    """

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
logging_setup(log_level="INFO")
app = create_app()
