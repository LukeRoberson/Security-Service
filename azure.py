# azure_auth.py
from flask import (
    Blueprint,
    session,
    redirect,
    url_for,
    request,
    jsonify,
    current_app
)

from functools import wraps
import msal
import uuid
import logging


# Azure scope for permissions
SCOPE = ['User.Read']

# Set up logging
logging.basicConfig(level=logging.INFO)


def get_azure_config():
    '''
    Returns the Azure configuration from the global config.
    '''

    return current_app.config['GLOBAL_CONFIG']['azure']


def get_auth_config():
    '''
    Returns the authentication configuration from the global config.
    '''

    logging.info("Getting auth config")
    logging.info("GLOBAL_CONFIG: %s", current_app.config['GLOBAL_CONFIG'])
    return current_app.config['GLOBAL_CONFIG']['authentication']


def get_msal_app():
    '''
    Returns an MSAL app instance for authentication.
    This is called as needed; It does not live for the lifetime of the app.
    '''

    auth_config = get_auth_config()
    azure_config = get_azure_config()
    return msal.ConfidentialClientApplication(
        auth_config['app-id'],
        authority=(
            f'https://login.microsoftonline.com/{azure_config["tenant-id"]}'
        ),
        client_credential=auth_config['app-secret'],
    )

# Create the MSAL app instance
# msal_app = msal.ConfidentialClientApplication(
#     auth_config['app-id'],
#     authority=f'https://login.microsoftonline.com/{azure_config["tenant-id"]}',
#     client_credential=auth_config['app-secret'],
# )


# Create a Flask blueprint for authentication
azure_auth = Blueprint('azure_auth', __name__)


def login_required(f):
    """
    Decorator to check if the user is logged in and has admin permissions.

    1. Checks if the user is in the session.
        - If not, redirects to the login page.
    2. Checks if the user is in the admin group.
        - If not, returns a 403 error.
    3. If both checks pass, calls the original function.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_config = get_auth_config()
        # Check if the user is logged in
        if 'user' not in session:
            logging.info("User not logged in")
            # User is not logged in, redirect to login
            return redirect(url_for('azure_auth.login', next=request.url))

        # Get a list of groups from the session
        groups = session.get('groups', [])

        # Check if the user is in the admin group
        if auth_config['admin-group'] not in groups:
            logging.warning("User not in admin group")
            return jsonify(
                {'error': 'You do not have permission for this resource.'}
            ), 403

        # User is logged in and has permission, call the original function
        logging.info("User is logged in and has permission")
        return f(*args, **kwargs)
    return decorated_function


@azure_auth.route('/login')
def login():
    '''
    Login Route - Redirected here if the user is not logged in.
    1. Tracks the URL the user was trying to access
    2. Generates a unique state for the session
    3. Redirects to the Azure AD login page
    '''

    msal_app = get_msal_app()

    # Track the URL the user was trying to access
    next_url = request.args.get('next')
    if next_url:
        session['next_url'] = next_url

    # Generate a unique state for the session
    session['state'] = str(uuid.uuid4())

    # Create the authorization URL
    auth_url = msal_app.get_authorization_request_url(
        SCOPE,
        state=session['state'],
        redirect_uri=url_for('azure_auth.authorized', _external=True)
    )

    # Redirect to the Azure AD login page
    return redirect(auth_url)


@azure_auth.route('/callback')
def authorized():
    '''
    Callback Route - Redirected here after Azure AD login.
    Azure will post the authorization code to this URL.

    1. Checks for errors in the request
    2. If no errors, retrieves the authorization code
    3. Exchanges the code for an access token
    4. If successful, stores the user info in the session
    5. Redirects to the original URL or home page
    '''

    # Check for errors in the request
    if 'error' in request.args:
        return (
            f"Error: {request.args['error']} - "
            f"{request.args.get('error_description')}"
        )

    # Get the code from the request (sent by Azure)
    msal_app = get_msal_app()
    code = request.args.get('code')
    if code:
        # Get a token from the code
        result = msal_app.acquire_token_by_authorization_code(
            code,
            scopes=SCOPE,
            redirect_uri=url_for('azure_auth.authorized', _external=True)
        )

        # Check if the token was successfully retrieved
        if 'access_token' in result:
            # Store the user info in the session
            session['user'] = result.get('id_token_claims')

            # Store the groups in the session
            session['groups'] = result.get('id_token_claims').get('groups', [])

            # Redirect to the original URL or home page
            next_url = session.pop('next_url', None)
            if next_url:
                return redirect(next_url)
            return redirect('/')

        # If the token was not retrieved, return an error
        return (
            f"Error: {result.get('error')} - "
            f"{result.get('error_description')}"
        )

    # If no code was provided, return an error
    return "No code provided"
