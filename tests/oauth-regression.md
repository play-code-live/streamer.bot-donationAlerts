# OAuth regression checklist — issue #9

Official API: https://www.donationalerts.com/apidoc (Authorization Code / Refreshing Access Tokens).

The previous implementation sent JSON to POST /oauth/token; the documented wire format is application/x-www-form-urlencoded for both grants. This is a confirmed mismatch, not proof that it caused the reported failures. Issue #9 does not include a status or OAuth error identifier.

## Setup

- Test a disposable Streamer.bot configuration. Back up actions and global variables. Replace the integration's inline C# with integration.cs from this branch, then compile and save. The release import files are not part of this change.
- Use a fresh browser authorization for each exchange. Authorization codes are single-use; never retry or share them.
- For controlled failure and wire-format tests, make a **local disposable copy** of the code with dummy client credentials and a loopback mock HTTP server in place of Client.TargetHost. Use only synthetic tokens/codes. Never route real credentials through a mock server or capture live HTTP bodies. Do not commit the local test configuration.
- Inspect only HTTP status, WebExceptionStatus, and allowlisted OAuth error identifiers in logs. Do not export full Streamer.bot globals, authorization links/callback URLs, request/response bodies, or raw logs containing credentials from previous versions.

## Scenarios

| Scenario | Expected |
| --- | --- |
| Fresh authorization via !da_connect with valid app registration and consent | Callback acknowledges the code; token exchange succeeds, access and refresh tokens are saved, and daCode is cleared. Profile and subscriptions work. |
| Mock authorization_code exchange | POST /oauth/token, Content-Type application/x-www-form-urlencoded; parsed form has grant_type, client_id, client_secret, code and redirect_uri. Redirect URI is unchanged after decoding (including trailing slash). |
| Special characters in synthetic code/secret (e.g. space, +, &, =, %, Cyrillic) | Form decoder round-trips original values; no double encoding or parameter injection. |
| Mock refresh_token exchange | Same form content type; parsed form contains grant_type, refresh_token, client_id, client_secret and space-delimited scope. |
| Refresh response with a new refresh token | Both new tokens are stored. |
| Refresh response with access token but no refresh token | Previous refresh token is retained. |
| Mock HTTP 400 with invalid_grant | Return false/null; logs identify grant type, HTTP status and invalid_grant; stored tokens remain unchanged, code is cleared. Start fresh authorization rather than retrying the code. |
| Mock HTTP 401 with invalid_client | Return false/null; logs identify status and invalid_client. Verify application credentials privately in the DA dashboard. |
| Mock HTTP 400 with invalid_scope or invalid_request | Return false/null; status and recognized OAuth error identifier are logged. |
| Mock error response containing synthetic secret in error_description, unknown error value, or HTML | No arbitrary response text or synthetic secret appears in logs; HTTP status is still recorded. |
| Unavailable local mock (connection refused) / DNS or TLS failure | WebException without an HTTP response is handled without NullReferenceException; transport status is logged. |
| HTTP 200 with malformed JSON, null, or missing access token; initial exchange without refresh token | Exchange fails without overwriting stored tokens or logging body/exception text. |
| Callback with missing code or OAuth error, including access_denied | Callback returns failure, no stale code is reused, browser does not report successful authorization. |
| Call ObtainAccessToken with null/empty/whitespace daCode | Return false without calling the token endpoint. |
| Existing Centrifugo subscription | POST /api/v1/centrifuge/subscribe continues using application/json and bearer authorization. Test donation and goal event delivery. |
| Logs after successful connection and refresh | No raw authorization code, access/refresh token, client secret, or profile JSON in the changed auth/profile logging paths. |

## If live authorization still fails

- invalid_client: verify registration and whether the existing application credential was rotated/revoked.
- invalid_grant: check fresh single-use code and exact registered redirect URI.
- invalid_scope: compare registered permissions with the requested scope list.
- HTTP 403/429/5xx or no HTTP response: investigate network, rate limit, upstream or transport separately.
- These are diagnostic directions, not confirmed causes for issue #9.

This patch does not rotate the existing embedded application credential or redesign the local OAuth callback/state flow. Treat a client secret distributed in public source as exposed; coordinate rotation and secure credential handling separately.
