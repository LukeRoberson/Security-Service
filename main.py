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


# Create the Flask application
app = Flask(__name__)


@app.route('/callback')
def callback():
    return flask.jsonify(
        {
            'result': 'success'
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
