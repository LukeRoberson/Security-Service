# Security Service

The security service manages anything related to security for the application as a whole. This includes:
* SSO with Azure, to login to the web UI
* Authentication of the Teams service account
* Token management for access to MS Teams
* Encryption and decryption of stings (for password management, etc)
* Validating signatures of webhook messages


</br></br>
----

# Project Organization
## Python Files

| File         | Provided Function                                             |
| ------------ | ------------------------------------------------------------- |
| main.py      | Entry point to the service, load configuration, set up routes |
| azure.py     | SSO auth, Teams auth, token retrieval                         |
| api.py       | API routes for interaction with other services                |
| crypto.py    | Encryption and decryption of strings                          |
| systemlog.py | Send system logs for the service to the logging service       |
| tokenmgmt.py | Manage tokens for 3rd party services (Azure)                  |


## Other Files

| File             | Description                                         |
| ---------------- | --------------------------------------------------- |
| .dockerignore    | Files that are excluded from the container image    |
| .gitignore       | Files that are excluded from git                    |
| Dockerfile       | For building the image                              |
| requirements.txt | Python modules and versions to install in the image |



</br></br>
----

# Authentication

There are two parts to authentication:
* SSO for access to the web UI
* Service account auth for Teams messages

Both types of authentication use registered apps in Azure.

SSO is used for access to the web UI, meaning there is no traditional login screen. There is also no storage of usernames and passwords locally for WebUI access.

A service account represents the Teams user (also see the Teams service). This user needs to be authenticated to get a berer token, which is used to send messages to teams.
</br></br>


## URL Protection

The security service provides a decorator called login_required(). The WebUI service can use this to add protection to each flask route.

Any route with this decorator requires an active user session before allowing access to that route.
</br></br>


## User Sessions

For WebUI access, Flask can track user sessions. This is required with authentication, so we can see if a user already has an authenticated session.

There are two critical parts to this:
1. Create a secret key for the Flask app. This signs session cookies for security
2. Share sessions across workers. This means setting a session type to ''filesystem'', ''redis'', or something else

When a user authenticates, their session is stored in the Flask app context. As they browse through WebUI pages, this session means that users don't need to authenticate with every page.
</br></br>


## Authentication Flow

1. User goes to a URL that requires authentication
    * This is identified by the @login_required decorator
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
# Token Management

Users authenticate with 3rd party services (Azure) and are given a token. This is true for logins to the WebUI and for the service account that accesses Teams.

These tokens are stored in an SQLite database. The database is created at startup within the container. When the container ends, the database is lost. In this way, security principles are not stored.

Information stored in the database include:
* The user name used in authentication
* The bearer token
* A refresh token
* A validity time
</br></br>


## Teams Service Account

To access Teams, a service account is used. This represents the chatbot user that messages come from.

This requires an app registration in Azure, with delegated permissions. Application level permissions are not supported by Azure for sending messages to chats (only channels are supported).

This means that the service account needs to authenticate in the same manner as a user would. The difference is that the user is not already logged on, so SSO is not possible.

In the WebUI, the 'about' page displays the current auth status of the service account. If it's not logged in, it provides a URL that a regular user can use to authenticate the service account.
</br></br>


## Token Refresh

Tokens are valid for a time, and then they expire. In Azure, this is 60 minutes by default.

If a token expires, the user is unauthenticated and will need to authenticate again. For SSO users to the WebUI, this is not a big deal as the user can reauthenticate easily. For the Teams service account, this is trickier as it requires manual intervention.

To work with this a refresh token is used. This is stored along with the bearer token.

A scheduled task runs to start the token refresh process before the 60 minutes expires. This yields a new bearer token and a new refresh token.

When this is done, the old token is removed from the database an the new one is added.
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
</br></br>


----
# Encryption and Decryption

Sensitive information will sometimes need to be stored in a configuration file or SQL database. This includes passwords/secrets to access devices and services. These can be encrypted for security.

The service can take a plain-text string and encrypt it. This yields:
* An encrypted string
* A corresponding salt string

It can also do the reverse. Providing an encrypted string and salt yields a plain-text string.

This process uses a master password along with AES256 to create very secure encryption. The Salt makes each encryption unique.

The master password is stored in the 'api_master_pw' environment variable. This should be passed to the container at runtime. It should never be stored in the docker image.

If the master password changes, encrypted strings will not be able to be decrypted again.
</br></br>


----
# API

There is an API in place so other services can access security functions.

| Endpoint           | Methods | Description                          |
| ------------------ | ------- | ------------------------------------ |
| /api/health        | GET     | Check the health of the container    |
| /api/hash          | POST    | Validate a signature for a webhook   |
| /api/crypto        | POST    | Encrypt or decrypt a string          |
| /api/token         | GET     | Request an existing token for a user |
| /api/refresh_token | GET     | Refresh an existing token            |
</br></br>


## Responses

Unless otherwise specified, all endpoints have a standard JSON response, including a '200 OK' message if everything is successful.

A successful response:
```
{
    'result': 'success'
}
```

An error:
```
{
    'result': 'error',
    'error': 'A description of the error'
}
```
</br></br>


## Health

Docker uses this endpoint to check the health of the container. If all is ok, this will respond with a '200 OK'
</br></br>


## Hash

Generates a hash signature for a given message using SHA256. This is compared to a signature send with a webhook to validate the message.

JSON Request (POST):
```
{
    'message': 'A message to hash',
    'secret': 'The secret key used in hashing',
    'signature': 'The signature to compare to'
}
```

A '401 Unauthorised' response is returned if the signature is invalid.
</br></br>


## Crypto

Encrypts or decrypts a string. Uses a 'type' string in the body to detemine which of the two operations are needed.
</br></br>


### Encryption

This takes a plain-text string, encrypts it, and returns the encrypted string along with a salt.

Request JSON:
```
{
    'type': 'encrypt',
    'plain-text': 'The string to encrypt'
}
```

Response JSON:
```
{
    'result': 'success',
    'encrypted': 'The encrypted string',
    'salt': 'The corresponding salt'
}
```
</br></br>


### Decryption

This takes an encrypted string and salt, and returns the plain-text string.

Request JSON:
```
{
    'type': 'decrypt',
    'encrypted': 'The encrypted string',
    'salt': 'The corresponding salt'
}
```

Response JSON:
```
{
    'result': 'success',
    'decrypted': 'The plain-text string'
}
```
</br></br>


## Token

This returns a bearer token for the Teams service account. This is not a request to authenticate a user with Azure and be issued a token.

This is a request to get a token from the token manager for a user that has previously been authenticated. This means that this endpoint can also be used to determine if the service account is currently authenticated.

As the service account is listed in the configuration file, there is no need to pass a username in this request.

Response JSON:
```
{
    'result': 'success',
    'user': 'The user ID corresponding to the token',
    'token': 'The token, as a string'
    'validity': An integer representing a valid cache time
}
```

To limit the calls to the security service, a short validity is included in the response, which tells the caller how long they can cache the response for. By default it is 60 seconds.

Once this has expired, the token must be requested again.

Note, this is not the expiry of the token itself. This is just how long the requester can cache the result ftom the security service.

A '404 Not Found' response is returned if the token is not in the database.
</br></br>


## Token Refresh

The token will need to be refreshed regularly. The scheduling service calls this endpoint to trigger this process.
