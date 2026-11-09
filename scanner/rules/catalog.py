"""
Rule catalog: static knowledge about every check the scanner can report.

Each rule declares its OWASP-style risk inputs (impact, likelihood), explanation, impact text,
remediation and reference. The final severity is NOT stored here: it is derived by
rules/severity.py so the model stays in one documented place.

References cite the OWASP Web Security Testing Guide v4.2 test identifiers.
No rule carries a CVSS score: none of these configuration checks maps to a verified CVSS
vector, and the scanner never invents one.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    impact: str            # Low | Medium | High    (damage if exploited)
    likelihood: str        # Low | Medium | High    (how likely the weakness is to be abused)
    reference: str
    method: str            # detection method shown to users
    description: str
    impact_text: str
    remediation: str
    dedupe_scope: str = 'host'


RULES = {}


def _r(rule_id, title, category, impact, likelihood, reference, method, description, impact_text, remediation,
       dedupe_scope='host'):
    RULES[rule_id] = Rule(rule_id, title, category, impact, likelihood, reference, method,
                          description, impact_text, remediation, dedupe_scope)


PASSIVE_HEADERS = 'Passive: HTTP response header inspection'
PASSIVE_COOKIES = 'Passive: Set-Cookie attribute inspection'
PASSIVE_BODY = 'Passive: response content inspection (signature match)'
ACTIVE_SAFE = 'Safe request: single allowlisted GET/OPTIONS, signature-validated'
TLS_PROBE = 'Safe probe: standard TLS handshake (no attack traffic)'

WSTG_CSP = 'OWASP WSTG-CONF-12 (Test Content Security Policy)'
WSTG_HSTS = 'OWASP WSTG-CONF-07 (Test HTTP Strict Transport Security)'
WSTG_CLICK = 'OWASP WSTG-CLNT-09 (Testing for Clickjacking)'
WSTG_HEADERS = 'OWASP Secure Headers Project; WSTG-CONF-12'
WSTG_COOKIE = 'OWASP WSTG-SESS-02 (Testing for Cookies Attributes)'
WSTG_TLS = 'OWASP WSTG-CRYP-01 (Testing for Weak Transport Layer Security)'
WSTG_ATHN = 'OWASP WSTG-ATHN-01 (Credentials Transported over an Encrypted Channel)'
WSTG_FINGER = 'OWASP WSTG-INFO-02 (Fingerprint Web Server)'
WSTG_ERR = 'OWASP WSTG-ERRH-01 (Testing for Improper Error Handling)'
WSTG_LEAK = 'OWASP WSTG-INFO-05 (Review Webpage Content for Information Leakage)'
WSTG_PLATFORM = 'OWASP WSTG-CONF-02 (Test Application Platform Configuration)'
WSTG_ADMIN = 'OWASP WSTG-CONF-05 (Enumerate Infrastructure and Application Admin Interfaces)'
WSTG_METHODS = 'OWASP WSTG-CONF-06 (Test HTTP Methods)'
WSTG_UNREF = 'OWASP WSTG-CONF-04 (Review Old Backup and Unreferenced Files)'

# ---------------------------------------------------------------- security headers
H = 'security_headers'
_r('HDR-CSP-MISSING', 'Content-Security-Policy header not set', H, 'Medium', 'Medium', WSTG_CSP, PASSIVE_HEADERS,
   'The response defines no Content-Security-Policy, neither as a header nor as a meta tag, so the browser '
   'applies no policy restricting where scripts and other resources may load from.',
   'A CSP is the main defence-in-depth control against cross-site scripting and content injection; without it '
   'any injection flaw is far easier to exploit.',
   'Define a restrictive Content-Security-Policy (start with default-src \'self\'; use nonces or hashes instead of '
   '\'unsafe-inline\'). Deploy in report-only mode first to find breakage.')
_r('HDR-CSP-REPORT-ONLY', 'Content-Security-Policy is report-only (not enforced)', H, 'Medium', 'Low', WSTG_CSP,
   PASSIVE_HEADERS,
   'Only Content-Security-Policy-Report-Only is sent. Violations are reported but nothing is blocked.',
   'The policy provides monitoring only; injected scripts still execute.',
   'Once reports show no legitimate violations, serve the policy in the enforcing Content-Security-Policy header.')
_r('HDR-CSP-MALFORMED', 'Content-Security-Policy header is present but malformed', H, 'Medium', 'Medium', WSTG_CSP,
   PASSIVE_HEADERS,
   'A Content-Security-Policy header is sent, but none of its policies contains a directive browsers recognise '
   '(it may be empty or garbled), so it is ignored and the page has no effective policy from it.',
   'The site appears to have a CSP but gets none of its protection, which also hides the gap from reviewers who '
   'only check that the header exists.',
   'Fix the header value: use valid directives separated by semicolons, e.g. '
   'Content-Security-Policy: default-src \'self\'; frame-ancestors \'none\'. Test it in the browser console.')
_r('HDR-CSP-META-ONLY', 'Content-Security-Policy set only through a <meta> tag', H, 'Low', 'Low', WSTG_CSP,
   PASSIVE_BODY,
   'The page defines its Content-Security-Policy only with <meta http-equiv="Content-Security-Policy"> and sends '
   'no Content-Security-Policy header. A meta policy is weaker than a header: browsers ignore frame-ancestors, '
   'report-uri and sandbox in it, it only applies to content parsed after the tag, and it cannot be report-only.',
   'Clickjacking protection and violation reporting are unavailable, and content that loads before the tag '
   'is not covered.',
   'Deliver the policy as a Content-Security-Policy HTTP header (keeping the meta tag is harmless), and set '
   'frame-ancestors there.')
_r('HDR-CSP-META-LATE', 'Content-Security-Policy <meta> tag placed after page content', H, 'Medium', 'Low',
   WSTG_CSP, PASSIVE_BODY,
   'The page sends no Content-Security-Policy header and its only policy is a <meta http-equiv> tag placed after '
   'content that loads or executes (a script, stylesheet, image or body content). Browsers apply a meta policy only '
   'to content parsed after the tag, so everything before it is outside the policy, and the usual meta limits '
   'apply too (no frame-ancestors, report-uri or sandbox).',
   'Scripts and resources that load before the tag are not restricted, so the policy gives only partial protection '
   'against injected content.',
   'Send the policy as a Content-Security-Policy HTTP header. If a meta tag must be used, make it the first '
   'element in <head>, before any script, stylesheet or other resource.')
_r('HDR-CSP-UNSAFE', 'Weak Content-Security-Policy', H, 'Medium', 'Low', WSTG_CSP, PASSIVE_HEADERS,
   'The script policy allows \'unsafe-inline\', \'unsafe-eval\', a wildcard or a whole scheme as a script source '
   'without a nonce/hash/strict-dynamic, which largely cancels the protection a CSP offers.',
   'Injected inline scripts, or scripts from any host matching the wildcard, can still run.',
   'Remove \'unsafe-inline\'/\'unsafe-eval\', replace wildcard and scheme sources with explicit hosts, and use '
   'nonces or hashes (optionally with \'strict-dynamic\').')
_r('HDR-HSTS-MISSING', 'Strict-Transport-Security header not set', H, 'Medium', 'Low', WSTG_HSTS, PASSIVE_HEADERS,
   'An HTTPS response does not send Strict-Transport-Security.',
   'Browsers may still be tricked into using plain HTTP (e.g. SSL-stripping on a hostile network) on the first '
   'or any later visit.',
   'Send Strict-Transport-Security: max-age=31536000; includeSubDomains on all HTTPS responses once every '
   'subdomain supports HTTPS.')
_r('HDR-HSTS-WEAK', 'Weak Strict-Transport-Security configuration', H, 'Medium', 'Low', WSTG_HSTS, PASSIVE_HEADERS,
   'The Strict-Transport-Security header has no valid max-age, or its max-age is below 180 days.',
   'A short lifetime leaves large windows where the browser will accept plain HTTP.',
   'Use max-age of at least 31536000 (one year); consider includeSubDomains and preload.')
_r('HDR-XCTO-MISSING', 'X-Content-Type-Options header not set', H, 'Low', 'Medium', WSTG_HEADERS, PASSIVE_HEADERS,
   'The response does not send X-Content-Type-Options: nosniff.',
   'Browsers may MIME-sniff responses and interpret user-controlled content as script or HTML.',
   'Send X-Content-Type-Options: nosniff on all responses and set correct Content-Type headers.')
_r('HDR-XCTO-INVALID', 'X-Content-Type-Options has an invalid value', H, 'Low', 'Medium', WSTG_HEADERS,
   PASSIVE_HEADERS,
   'X-Content-Type-Options is present but its value is not "nosniff", so browsers ignore it.',
   'MIME sniffing protection is not active.', 'Set the header value to exactly: nosniff')
_r('HDR-XFO-MISSING', 'No clickjacking protection (X-Frame-Options / frame-ancestors)', H, 'Medium', 'Low',
   WSTG_CLICK, PASSIVE_HEADERS,
   'The page can be embedded in frames of other sites: it sets neither X-Frame-Options nor a CSP '
   'frame-ancestors directive.',
   'An attacker can overlay the page in a hidden frame and trick users into clicking (clickjacking).',
   'Send Content-Security-Policy: frame-ancestors \'self\' (or \'none\') and, for older browsers, '
   'X-Frame-Options: DENY or SAMEORIGIN.')
_r('HDR-FRAME-ANCESTORS-WEAK', 'CSP frame-ancestors does not restrict framing', H, 'Medium', 'Low', WSTG_CLICK,
   PASSIVE_HEADERS,
   'The Content-Security-Policy header contains a frame-ancestors directive that allows framing by any site (a * or '
   'a bare scheme source such as https:). While frame-ancestors is enforced, browsers ignore X-Frame-Options, so '
   'the page is left without effective clickjacking protection.',
   'An attacker can overlay the page in a hidden frame and trick users into clicking (clickjacking).',
   'Set frame-ancestors to \'none\', \'self\' or an explicit list of trusted origins, e.g. '
   'Content-Security-Policy: frame-ancestors \'self\' https://partner.example')
_r('HDR-XFO-WEAK', 'X-Frame-Options has an obsolete or invalid value', H, 'Medium', 'Low', WSTG_CLICK,
   PASSIVE_HEADERS,
   'X-Frame-Options is set to a value other than DENY or SAMEORIGIN (for example the obsolete ALLOW-FROM), '
   'which modern browsers ignore.',
   'Clickjacking protection may not be applied.',
   'Use X-Frame-Options: DENY or SAMEORIGIN, and CSP frame-ancestors for finer control.')
_r('HDR-REFERRER-MISSING', 'Referrer-Policy header not set', H, 'Low', 'Low', WSTG_HEADERS, PASSIVE_HEADERS,
   'No Referrer-Policy is defined (header or meta tag); the browser default applies.',
   'Full URLs, which may contain sensitive identifiers, can leak to other sites through the Referer header.',
   'Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).')
_r('HDR-REFERRER-WEAK', 'Referrer-Policy leaks full URLs', H, 'Low', 'Medium', WSTG_HEADERS, PASSIVE_HEADERS,
   'Referrer-Policy is set to unsafe-url, sending the full URL, including query string, to every destination.',
   'Sensitive URL parameters and paths can be disclosed to third parties, even over plain HTTP.',
   'Use strict-origin-when-cross-origin, same-origin or no-referrer.')
_r('HDR-PERMISSIONS-MISSING', 'Permissions-Policy header not set', H, 'Low', 'Low', WSTG_HEADERS, PASSIVE_HEADERS,
   'No Permissions-Policy restricts browser features such as camera or geolocation. The deprecated '
   'Feature-Policy header is not accepted as a substitute: it was superseded, uses a different syntax and is not '
   'consistently supported.',
   'Embedded third-party content may use powerful browser features unless the browser default denies them.',
   'Send a Permissions-Policy that disables features the application does not use, e.g. '
   'Permissions-Policy: camera=(), microphone=(), geolocation=()')

# ---------------------------------------------------------------- cookies
C = 'cookie_security'
_r('COOKIE-NO-SECURE', 'Cookie without the Secure attribute', C, 'Medium', 'Medium', WSTG_COOKIE, PASSIVE_COOKIES,
   'A cookie is set over HTTPS without the Secure attribute, so browsers will also send it over plain HTTP.',
   'The cookie can be captured by a network attacker whenever the browser makes any HTTP request to the site.',
   'Add the Secure attribute to every cookie issued over HTTPS.', 'host')
_r('COOKIE-NO-HTTPONLY', 'Cookie without the HttpOnly attribute', C, 'Medium', 'Medium', WSTG_COOKIE,
   PASSIVE_COOKIES,
   'A cookie is set without HttpOnly, so client-side script can read it.',
   'If the site has a cross-site scripting flaw, the cookie (for session cookies: the session) can be stolen.',
   'Add HttpOnly to cookies that scripts do not need to read, especially session and authentication cookies.')
_r('COOKIE-SAMESITE-MISSING', 'Cookie without a valid SameSite attribute', C, 'Low', 'Medium', WSTG_COOKIE,
   PASSIVE_COOKIES,
   'A cookie sets no (or an invalid) SameSite attribute, so it relies on browser defaults.',
   'Behaviour differs between browsers and versions; cross-site request forgery protection is not explicit.',
   'Set SameSite=Lax (or Strict where possible) explicitly.')
_r('COOKIE-SAMESITE-NONE', 'Cookie sent on all cross-site requests (SameSite=None)', C, 'Medium', 'Low',
   WSTG_COOKIE, PASSIVE_COOKIES,
   'The cookie uses SameSite=None, so the browser attaches it to cross-site requests.',
   'Increases exposure to cross-site request forgery and cross-site leaks if the cookie authenticates the user. '
   'Browsers also reject SameSite=None cookies that lack Secure.',
   'Use SameSite=Lax or Strict unless cross-site delivery is genuinely required, and always combine None with Secure.')
_r('COOKIE-PREFIX-INVALID', 'Cookie violates its __Host-/__Secure- prefix rules', C, 'Low', 'Medium', WSTG_COOKIE,
   PASSIVE_COOKIES,
   'The cookie name uses a __Host- or __Secure- prefix but lacks the attributes the prefix requires, so browsers '
   'reject it and the intended protection is lost.',
   'The cookie will not be stored, or the application assumes protections that do not exist.',
   '__Secure- requires Secure; __Host- requires Secure, Path=/ and no Domain attribute.')
_r('COOKIE-BROAD-DOMAIN', 'Session-like cookie shared with subdomains (Domain attribute)', C, 'Low', 'Medium',
   WSTG_COOKIE, PASSIVE_COOKIES,
   'A cookie with a session/authentication-like name sets the Domain attribute, making it available to every '
   'subdomain. This is a heuristic based on the cookie name.',
   'A compromised or less trusted subdomain can read or overwrite the cookie.',
   'Omit the Domain attribute (host-only cookie) unless sharing across subdomains is required.')
_r('COOKIE-SENSITIVE-OVER-HTTP', 'Session-like cookie set over unencrypted HTTP', C, 'Medium', 'Medium', WSTG_COOKIE,
   PASSIVE_COOKIES,
   'A cookie with a session/authentication-like name is issued in a plain HTTP response. Whether it really '
   'carries a session is inferred from its name.',
   'Anyone able to observe the network can read the cookie.',
   'Serve the application over HTTPS only and mark cookies Secure.')

# ---------------------------------------------------------------- TLS
T = 'ssl_tls'
_r('TLS-CERT-EXPIRED', 'TLS certificate has expired', T, 'Medium', 'High', WSTG_TLS, TLS_PROBE,
   'The server presented a certificate whose validity period has ended.',
   'Browsers show security warnings and users learn to click through them, which also enables interception.',
   'Renew and deploy a valid certificate; automate renewal (e.g. ACME).')
_r('TLS-CERT-NOT-YET-VALID', 'TLS certificate is not yet valid', T, 'Medium', 'Medium', WSTG_TLS, TLS_PROBE,
   'The certificate validity period has not begun (or the server clock is wrong).',
   'Clients reject the connection or show warnings.', 'Check the certificate dates and the server clock.')
_r('TLS-CERT-HOSTNAME-MISMATCH', 'TLS certificate does not match the host name', T, 'Medium', 'High', WSTG_TLS,
   TLS_PROBE,
   'The certificate is not valid for the host name that was requested.',
   'Clients cannot verify they reached the intended server, enabling interception after a click-through.',
   'Issue a certificate whose subject alternative names include this host name.')
_r('TLS-CERT-SELF-SIGNED', 'TLS certificate is self-signed', T, 'Medium', 'High', WSTG_TLS, TLS_PROBE,
   'The certificate is not issued by a trusted certificate authority.',
   'Clients cannot authenticate the server, so a man-in-the-middle cannot be told apart from the real site.',
   'Use a certificate from a publicly trusted CA (or a private CA that clients are configured to trust).')
_r('TLS-CERT-UNTRUSTED', 'TLS certificate chain is not trusted or incomplete', T, 'Medium', 'Medium', WSTG_TLS,
   TLS_PROBE,
   'The certificate chain could not be validated against trusted roots (unknown issuer or missing '
   'intermediate certificate).',
   'Some or all clients will reject the connection or show warnings.',
   'Serve the complete chain (leaf plus intermediates) from a trusted CA.')
_r('TLS-CERT-INVALID', 'TLS certificate failed validation', T, 'Medium', 'Medium', WSTG_TLS, TLS_PROBE,
   'Certificate validation failed for a reason not covered by a more specific check (see evidence).',
   'Clients may refuse the connection or show warnings.', 'Resolve the validation error reported in the evidence.')
_r('TLS-CERT-EXPIRING-SOON', 'TLS certificate expires soon', T, 'Low', 'Medium', WSTG_TLS, TLS_PROBE,
   'The certificate is valid but expires within 30 days.',
   'An expired certificate causes outages and browser warnings.', 'Renew the certificate before it expires.')
_r('TLS-PROTOCOL-OBSOLETE', 'Obsolete TLS protocol version accepted', T, 'Medium', 'Medium', WSTG_TLS, TLS_PROBE,
   'The server completed a handshake using TLS 1.0 or TLS 1.1, which are deprecated (RFC 8996).',
   'These versions have known weaknesses and fail modern compliance baselines (e.g. PCI DSS).',
   'Disable TLS 1.0 and 1.1; support TLS 1.2 and 1.3 only.')
_r('TLS-LEGACY-UNTESTED', 'Legacy TLS versions could not be tested from the scanner host', T, 'Low', 'Low',
   WSTG_TLS, TLS_PROBE,
   'The scanner\'s local TLS library refuses to attempt TLS 1.0/1.1, so whether the server accepts them is unknown. '
   'This is NOT evidence that the server is secure.',
   'Obsolete protocol support remains unverified.',
   'Verify with a dedicated TLS testing tool run from a host that can negotiate legacy versions.')
_r('TLS-HTTP-NO-REDIRECT', 'HTTP does not redirect to HTTPS', T, 'Medium', 'Medium', WSTG_TLS, ACTIVE_SAFE,
   'The same host answers a plain HTTP request with content instead of redirecting to HTTPS.',
   'Users who type the address or follow an http:// link are served unencrypted content and can be intercepted.',
   'Redirect all HTTP requests to HTTPS (301) and send HSTS.')
_r('TLS-HTTP-ONLY', 'Application is served over unencrypted HTTP', T, 'Medium', 'Medium', WSTG_TLS, PASSIVE_HEADERS,
   'The scanned target is served over plain HTTP.',
   'Traffic, including any cookies and form data, can be read or modified in transit.',
   'Serve the application over HTTPS with a valid certificate and redirect HTTP to HTTPS.')
_r('TLS-LOGIN-OVER-HTTP', 'Password form served over unencrypted HTTP', T, 'High', 'Medium', WSTG_ATHN,
   PASSIVE_BODY,
   'A page served over plain HTTP contains a password input field.',
   'Credentials entered by users can be captured on the network.',
   'Serve every page containing login forms over HTTPS only.', 'url')

# ---------------------------------------------------------------- information disclosure
I = 'information_disclosure'
_r('INFO-TECH-DISCLOSURE', 'Server technology disclosed in response headers', I, 'Low', 'Medium', WSTG_FINGER,
   PASSIVE_HEADERS,
   'A response header reveals the software in use (and, where noted in the evidence, its version).',
   'Attackers can target known vulnerabilities of the disclosed product and version.',
   'Remove or genericise Server, X-Powered-By and similar headers (e.g. ServerTokens Prod, server_tokens off, '
   'expose_php=Off).')
_r('INFO-VERBOSE-ERROR', 'Verbose error message / stack trace exposed', I, 'Medium', 'Medium', WSTG_ERR, PASSIVE_BODY,
   'A response contains a framework error page or stack trace revealing code paths, library versions or query text.',
   'Internal details help attackers craft targeted attacks.',
   'Return generic error pages in production and log details server-side only.', 'url')
_r('INFO-DEBUG-MODE', 'Application debug mode / debug console exposed', I, 'High', 'Medium', WSTG_ERR, PASSIVE_BODY,
   'The response is produced by an application running in debug mode (for example a debugger console or debug '
   'error page).',
   'Debug interfaces can expose source code, configuration and secrets and may allow remote code execution.',
   'Disable debug mode in production and never expose debugger consoles.', 'url')
_r('INFO-DEBUG-HEADER', 'Debug information exposed in response headers', I, 'Medium', 'Medium', WSTG_ERR,
   PASSIVE_HEADERS,
   'Response headers reveal debugging/profiling facilities (for example Symfony X-Debug-Token).',
   'Profiler data can expose internal requests, configuration and queries.',
   'Disable the profiler and debug headers in production.')
_r('INFO-SECRET-EXPOSED', 'Sensitive-looking credential exposed in a public response', I, 'High', 'Medium',
   WSTG_LEAK, PASSIVE_BODY,
   'A public response contains a value matching the format of a credential. The value is NOT stored or '
   'displayed by the scanner.',
   'Exposed credentials can be used to access systems or data.',
   'Treat the credential as compromised: revoke and rotate it, and remove it from public content.', 'url')
_r('INFO-INTERNAL-IP', 'Internal IP address disclosed', I, 'Low', 'Medium', WSTG_LEAK, PASSIVE_BODY,
   'A public response contains a private (RFC 1918) IP address, which may reveal internal network layout.',
   'Internal addressing helps attackers map the network behind the site.',
   'Remove internal addresses from responses, headers and error messages.', 'url')

# ---------------------------------------------------------------- security configuration
S = 'security_configuration'
_r('CFG-DIR-LISTING', 'Directory listing enabled', S, 'Medium', 'Medium', WSTG_UNREF, PASSIVE_BODY,
   'A page is an automatically generated directory index, letting visitors browse files on the server.',
   'Unlinked files, backups and source can be discovered and downloaded.',
   'Disable directory indexing (Apache: Options -Indexes; nginx: autoindex off) and review exposed files.', 'url')
_r('CFG-PHPINFO', 'phpinfo() page exposed', S, 'Medium', 'Medium', WSTG_PLATFORM, ACTIVE_SAFE,
   'A publicly reachable page outputs the PHP configuration.',
   'Reveals versions, paths, modules and environment values that assist attacks.',
   'Delete diagnostic scripts from production.', 'url')
_r('CFG-SERVER-STATUS', 'Web server status page exposed', S, 'Medium', 'Medium', WSTG_ADMIN, ACTIVE_SAFE,
   'The Apache mod_status page is publicly reachable.',
   'Exposes request URLs, client addresses and server load.',
   'Restrict /server-status to trusted addresses or disable mod_status.', 'url')
_r('CFG-API-DOCS', 'API documentation endpoint publicly exposed', S, 'Low', 'Medium', WSTG_ADMIN, ACTIVE_SAFE,
   'Machine- or human-readable API documentation (Swagger/OpenAPI/ReDoc) is publicly reachable.',
   'Gives attackers a complete map of endpoints and parameters.',
   'Restrict documentation to authenticated/internal users in production if the API is not public.', 'url')
_r('CFG-ACTUATOR', 'Spring Boot Actuator endpoints exposed', S, 'Medium', 'Medium', WSTG_ADMIN, ACTIVE_SAFE,
   'The Spring Boot Actuator index is publicly reachable.',
   'Actuator endpoints can reveal configuration, metrics and sometimes allow state changes.',
   'Restrict management endpoints to a separate port or authenticated users and expose only what is needed.', 'url')
_r('CFG-ACTUATOR-ENV', 'Spring Boot Actuator /env endpoint exposed', S, 'High', 'Medium', WSTG_ADMIN, ACTIVE_SAFE,
   'The Actuator environment endpoint returns application configuration properties.',
   'Configuration frequently contains credentials and internal addresses (the scanner does not store the values).',
   'Disable or secure /actuator/env and rotate any secrets that may have been exposed.', 'url')
_r('CFG-HTTP-METHODS', 'Risky HTTP method advertised', S, 'Medium', 'Low', WSTG_METHODS, ACTIVE_SAFE,
   'The server\'s response to an OPTIONS request lists a method such as TRACE, PUT or DELETE. The method itself '
   'was NOT executed, so this is based on what the server advertises.',
   'TRACE can aid cross-site tracing; PUT/DELETE may allow unauthorised modification if not access-controlled.',
   'Disable methods the application does not need and require authorisation for state-changing methods.')
