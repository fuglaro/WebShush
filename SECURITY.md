# Security Design
Since this service proxies SSH credentials, and streams personal data, hardened web security policies have been implemented.

## Transport Security
* The login form will not open unless the connection protocol is HTTPS.
* HTTP requests to the main page are redirected to HTTPS (if port 8080 isn't already used).
* The backend implements a strict HTTPS ONLY policy.
* HTTP Strict Transport Security (HSTS) is enabled.
* All WebSocket connections use WebSocket Secure (WSS).
* The backend supports being provided TLS credentials otherwise it uses an included certbot integration.
* The webserver connects to the SSH service with Strict Host Key Checking, if a host key is provided, otherwise it will retrieve the host key and load it into the login form and URL for future validation.

## Authentication
* Authentication is made by proxying the SSH credentials through the backend in establishing an SSH connection managed by the backend.
* This primarily relies on SSH username and password authentication.
* 2FA can be additionally configured with a Pluggable Authentication Module (PAM).

## Login Session Managment
* On completion of the login form, an authenticated secure connection is established:
  * A WebSocket connection is established with the backend (with WSS).
  * The login credentials are passed directly to the WebSocket connection.
  * The backend passes the credentials directly into establishing an SSH connection.
  * The SSH connection is attached to the WebSocket connection to handle future communication.
  * The credentials are not stored in any persistent way.
  * Failure to establish an authenticated SSH connection will close the WebSocket connection, triggering a new login sequence.
  * After sending the credentials to the WebSocket connection, the login form will pass the potentially authenticated WebSocket connection to be stored inside an instance of the Server class in a private variable, so as to restrict direct access from JavaScript except via its API.
* The user may choose to store the credentials in the browser's password management system, if supported and enabled in the browser. For additial security, 2FA is recommended.
* Logout occurs when either the browser or the backend closes the WebSocket connection, such as:
  * Automatically when closing or refreshing the browser tab.
  * When restarting the backend service.
  * From a disruption to the network connection.

## Site Isolation and Content Protection
* Same-Origin Policy is enforced.
* Cross Origin Isolation is enforced by:
  * Setting the Cross Origin Opener Policy to ensure the browsing context is exclusively isolated to same-origin documents.
  * Setting the Cross Origin Embedder Policy to require corp (Cross Origin Resource Policy).
  * Ensuring Cross Origin Isolation is fully activated by checking that the crossOriginIsolated property in the browser is active, before opening the login form.
  * Default Cross Origin Read Blocking browser protections are enhanced by all Content Type Options being configured with nosniff, and with the Content-Type header being set.
* Cross Origin Resource Policy is configured to same-origin so that all resources are protected from access by any other origin.
* Content Security Policy is enforced with a configuration that ensures:
  * Image, font and media content can be loaded only from the site's own origin.
  * Script resources can be loaded only from the site's own origin or from inline elements protected with a 128 bit cryptographically secure random nonce.
  * Stylesheet resources can be loaded only from the site's own origin or from inline elements.
  * WebSockets can only be connected to the site own origin.
  * Contents that do not match the above types, are denied.
  * All content is loaded sandboxed with restricted allowances.
  * Documents are prevented from being embedded.
  * Forms are denied from using URLs as the target of form submission.
* The backend requires the browser to provide Secure Fetch Metadata Request Headers, and denies access to content unless the following policies are met:
  * For the main page:
    * The request destination is a document, preventing embedding.
  * For the `/resources/` URL path:
    * The request site is same-origin.
    * The request destination is a script, style or font element.
  * For the `/preconnect` endpoint:
    * The request site is same-origin.
    * The request destination is set to the word empty.
  * For the `/connect` endpoint:
    * If any site, mode, or destination Secure Fetch Metadata Headers are provided, then they must all match the policy:
      * The request site is same-origin.
      * The request mode is a websocket.
      * The request destination is set to the word empty (Firefox) or websocket (Safari).
    * Unfortunately, Chromium based browsers do not send any Secure Fetch Metadata Headers (as of Chrome Version 123.0.6312.124) when establishing WebSocket connections. To ensure the /connect endpoint is still protected by a same-origin site check, this endpoint expects a __Host-SecSiteSameOrigin cookie to contain a valid JWT with valid expiration and audience claims, which can only be obtained from the /preconnect endpoint as a SameSite=Strict cookie after its own checks that the site is same origin. The JWT provided by the /preconnect endpoint is given an audience claim of the client IP, and an expiration claim of 3 seconds after the time of creation.
* The backend enforces a browser cache policy which ensures cached content access adheres to the above Secure Fetch Metadata Request Header policy, including when the headers vary across subsequent requests.
* A Referrer Policy of same-origin is enforced.

## Additional Cross-Site Request Forgery (CSRF/XSRF) Protection
* The login form is protected with a CSRF Token secured by an HMAC-SHA256 Signed Double-Submit Cookie.
* All backend endpoints which cause any changes or side effects (besides server load or establishing authentication), are only accessible through the WebSocket connection.
* The WebSocket connection is stored in a private variable, inside the Storage class, and is only accessible via it's restricted API.

## Third-Party Dependencies
* All third-party dependencies are servered from the backend and are version controlled and stored locally.
* All third-party dependencies loaded in the browser are Subresource Integrity checked.
* Cache-Control is enforced so the browser caches content for no longer than 10 hours.

