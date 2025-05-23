# Security Module

Handles anything related to security, including:
* Authentication
* Encryption


</br></br>
----

# Authentication

Authentication uses an app in Azure. There is no traditional login screen.

## Sessions

Flask can track user sessions. This is required with authentication, so we can see if a user already has a session open.

There are two main parts to this:
1. Create a secret key for the Flask app. This signs session cookies for security
2. Share sessions across workers. This means setting a session type to ''filesystem'', ''redis'', or something else


## Authentication Flow

1. User goes to a URL that requires authentication
    * This is identified by the @loginrequired decorator
2. The decorator checks if the current user has an active session
    * If yes, group membership is checked
    * If that's ok, access to the URL is allowed
    * If there is no session, the user is redirected to /login, where they need to authenticate
3. The MSAL library generates a URL that the user is redirected to
    * This is on the Microsoft site, external to the app
    * The user can then submit credentials
4. Azure allows or denies the user
5. Azure sends a message to the /callback URL with the result
    * If successful, there will be a code in the body
    * A session token is extracted from the code
    * The token is added to the current session (tracks that the user is logged in)
6. If auth is successful, the user is redirected to their original URL

