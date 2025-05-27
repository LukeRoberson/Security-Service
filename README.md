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


</br></br>
----

# Signature Validation

A webhook is often sent with a signature (although this depends on the sender) to ''sign'' the contents of the webhook.

We can use this to validate that this webhook was sent from a valid source. This relies on the sender being configured to use a **secret**.


## HMAC_SHA256

One common way is for the sender to generate the signature and attach it as a header.

The sender will:
1. Concatenate the secret with the message body (in that order) to create a string
2. Generate a hash using HMAC_SHA256 on that string
3. Attach that string as a header to the original message
4. Send the webhook as normal

Mist, for example, will attach the **X-Mist-Signature-v2** header to include the secret.

Note, some webhook senders may use different security algorithms. Mist for example, also supports using the **HMAC_SHA1** algorithm, sent in the **X-Mist-Signature** header.

When the webhook is received, the receiver can perform the same steps to verify the sender:
1. Extract the signature header
2. Concatenate the known secret to the body to get a string
3. Generate a hash
4. Compare the hash to the contents of the signature in the header

