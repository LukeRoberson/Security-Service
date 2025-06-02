"""
Module to manage Azure AD.
    - Handles user authentication via Azure AD.

Functions:
    - get_azure_config: Returns the Azure configuration from the global config.
    - get_auth_config: Returns the authentication configuration
        from the global config.
    - get_msal_app: Returns an MSAL app instance for authentication.
    - login_required: Decorator to check if the user is logged in and
        has admin permissions.

Routes:
    - login: Route to handle user login, redirecting to Azure AD.
    - authorized: Callback route to handle Azure AD login response and
        store user info.d
"""


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

from tokenmgmt import TokenManager


# Azure scope for permissions
SCOPE = ['User.Read']

# Create a Flask blueprint for authentication
azure_auth = Blueprint(
    'azure_auth',
    __name__
)


def get_azure_config():
    '''
    Returns the Azure configuration from the global config.
    '''

    return current_app.config['GLOBAL_CONFIG']['azure']


def get_auth_config():
    '''
    Returns the authentication configuration from the global config.
    '''

    logging.debug("Getting auth config")
    logging.debug("GLOBAL_CONFIG: %s", current_app.config['GLOBAL_CONFIG'])
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


def login_required(f):
    """
    Decorator to check if the user is logged in and has admin permissions.

    1. Checks if the user is in the session.
        - If not, redirects to the login page.
    2. Checks if the user is in the admin group.
        - If not, returns a 403 error.
    3. If both checks pass, calls the original function.

    Include 'prompt=login' parameter in the URL to force the user
        to log in, even if they are already logged in to Azure AD.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_config = get_auth_config()
        # Check if the user is logged in
        if 'user' not in session:
            logging.info("User not logged in")
            # User is not logged in, redirect to login
            return redirect(
                url_for(
                    'azure_auth.login',
                    next=request.url,
                    # prompt='login',
                )
            )

        # Get a list of groups from the session
        groups = session.get('groups', [])

        # Check if the user is in the admin group
        if auth_config['admin-group'] not in groups:
            logging.warning("User not in admin group")
            return jsonify(
                {
                    'result': 'error',
                    'error': 'You do not have permission for this resource.',
                    'user': session.get(
                        'user',
                        {}
                    ).get(
                        'preferred_username',
                        'unknown'
                    ),
                    'groups': groups,
                }
            ), 403

        # User is logged in and has permission, call the original function
        logging.info("User is logged in and has permission")
        return f(*args, **kwargs)
    return decorated_function


@azure_auth.route(
    '/login',
    methods=['GET']
)
def login():
    '''
    Login Route - Redirected here if the user is not logged in.
    1. Tracks the URL the user was trying to access
    2. Generates a unique state for the session
    3. Redirects to the Azure AD login page

    get_authorization_request_url() is used to generate the URL for login.
        This URL contains the necessary parameters for Azure AD to
        authenticate the user and redirect back to the application.
    When SSO is configured, the username is passed automatically
        The user doesn't have to do anything. They briefly see the
        Azure AD login page, and then they are redirected back to the app.
    When the 'prompt' parameter is set to 'login', the user is forced to
        provide credentials, even if they are already logged in to Azure AD.
        This is useful to authenticating service accounts
    The 'login_hint' parameter is used to pre-fill the username with a
        suggested username. The user can change it if they want.

    Include the 'prompt=login' parameter in the URL to force
        the user to log in, even if they are already logged in to Azure AD.
    '''

    msal_app = get_msal_app()

    # Track the URL the user was trying to access
    next_url = request.args.get('next')
    if next_url:
        session['next_url'] = next_url

    # Generate a unique state for the session
    session['state'] = str(uuid.uuid4())

    # Check if 'prompt' mode is specified in the request
    prompt_mode = request.args.get('prompt', None)
    if prompt_mode:
        # Enables the 'prompt' parameter in the authorization request
        prompt_value = prompt_mode
        login_hint = "serviceaccount@domain.com"
    else:
        prompt_value = None
        login_hint = None

    # Create the authorization URL
    auth_url = msal_app.get_authorization_request_url(
        SCOPE,
        state=session['state'],
        redirect_uri=url_for('azure_auth.authorized', _external=True),
        prompt=prompt_value,
        login_hint=login_hint
    )
    logging.info("Redirecting to Azure AD login page")
    logging.debug("Auth URL: %s", auth_url)

    # Redirect to the Azure AD login page
    return redirect(auth_url)


@azure_auth.route('/callback')
def authorized():
    '''
    Callback Route - Redirected here after Azure AD login.
        Azure will post the authorization code to this URL.

    TokenManager is the class used to store and manage tokens.

    1. Checks for errors in the request
    2. If no errors, retrieves the authorization code
    3. Exchanges the code for an access token
    4. If successful, stores the user info in the session and TokenManager
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
        logging.debug(
            "Result from MSAL acquire_token_by_authorization_code: %s",
            result
        )

        # Check if the token was successfully retrieved
        if 'access_token' in result:
            # Store useful fields
            access_token = result['access_token']
            refresh_token = result.get('refresh_token', None)
            expiry = result['id_token_claims']['exp']
            user_id = result['id_token_claims']['preferred_username']
            logging.debug(
                "Access token acquired for user: %s", user_id
            )

            # Store the token in the TokenManager
            with TokenManager() as token_manager:
                token_manager.add_token(
                    user_id=user_id,
                    bearer_token=access_token,
                    refresh_token=refresh_token,
                    expiration=expiry,
                )
                logging.debug(
                    "Token stored for user: %s", user_id
                )

            # Store the user info in the session
            session['user'] = result.get('id_token_claims')
            logging.debug("User info stored in session: %s", session['user'])

            # Store the groups in the session
            session['groups'] = result.get('id_token_claims').get('groups', [])
            logging.debug(
                "User groups stored in session: %s",
                session['groups']
            )

            # Redirect to the original URL or home page
            next_url = session.pop('next_url', None)
            if next_url:
                logging.info("Redirecting to original URL: %s", next_url)
                return redirect(next_url)
            return redirect('/')

        # If the token was not retrieved, return an error
        logging.error(
            "Failed to acquire token by authorization code: %s",
            result
        )
        return (
            f"Error: {result.get('error')} - "
            f"{result.get('error_description')}"
        )

    # If no code was provided, return an error
    logging.error("No code provided in the request")
    return "No code provided"
