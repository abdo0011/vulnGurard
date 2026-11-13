"""
Feature 2: passive cookie security detection (Secure, HttpOnly, SameSite, prefixes, scope, redaction).

The detector reads only the Set-Cookie headers of responses the crawler already collected. These tests cover the
parser, every rule, aggregation limits, the guarantee that a cookie VALUE never leaves the parser, and real scans
through the engine.
"""
import hashlib
import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.crawler import Page
from scanner.detectors import CATEGORIES, get_detectors
from scanner.detectors.cookie_security import (MAX_COOKIES_PER_RESPONSE, MAX_DIGEST_CHARS, MAX_LABEL_PREFIX, MAX_NAME_CHARS, MAX_NAMES_PER_RULE, MAX_PARSED_NAME,
                                               CookieSecurityDetector, _parse_max_age, cookie_label, csrf_kind, display_name, is_session_like,
                                               is_trustworthy_host, parse_set_cookie, prefix_is_exact, prefix_kind)
from scanner.engine import ScanEngine
from scanner.http_client import HttpResponse, ScanHTTPClient
from scanner.rules import get_rule
from scanner.rules.catalog import RULES

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)
HARD = 'Secure; HttpOnly; SameSite=Lax'


def resp(url='https://a.test/', cookies=(), status=200, header_name='Set-Cookie', extra_headers=()):
    headers = [('Content-Type', 'text/html')] + [(header_name, c) for c in cookies] + list(extra_headers)
    return HttpResponse(url=url, method='GET', status=status, reason='', headers=headers, body=b'<html></html>',
                        truncated=False, ip='93.184.216.34', scheme=url.split(':')[0])


def detect(*responses, client=None):
    pages = [Page(r.url, 0, r) for r in responses]
    return CookieSecurityDetector().run(SimpleNamespace(pages=pages, client=client, target=None, config=None))


def cookies(url, *headers):
    return detect(resp(url, headers))


def rules(findings):
    return {f.extra['rule'] for f in findings}


def only(findings, rule):
    match = [f for f in findings if f.extra['rule'] == rule]
    assert len(match) == 1, f'{rule}: {len(match)} findings in {sorted(rules(findings))}'
    return match[0]


def names(findings, rule):
    return sorted(f.extra['cookie_name'] for f in findings if f.extra['rule'] == rule)


# ================================================================ parser
def test_parser_never_keeps_the_cookie_value():
    c = parse_set_cookie('sid=SECRETVALUE123; Secure; HttpOnly')
    assert c.name == 'sid'
    for text in (repr(c), str(c), str(c._asdict()), str(tuple(c))):
        assert 'SECRETVALUE123' not in text
    assert not any(isinstance(v, str) and 'SECRET' in v for v in c)


def test_parser_reads_attributes_case_insensitively_and_trims_whitespace():
    c = parse_set_cookie(' sid = x ;  SECURE ; httponly;SameSite = LAX ; DOMAIN=.Example.COM ; path=/a')
    assert (c.name, c.secure, c.httponly, c.samesite, c.domain, c.path) == ('sid', True, True, 'lax', 'example.com', '/a')
    assert c.conflicts == () and c.deleted is False


def test_flag_attributes_count_by_presence_even_with_a_value():
    c = parse_set_cookie('a=b; Secure=false; HttpOnly=0')
    assert c.secure and c.httponly


def test_value_may_contain_equals_signs_and_the_name_is_only_what_precedes_the_first_one():
    assert parse_set_cookie('a=b=c==; Secure').name == 'a'


@pytest.mark.parametrize('raw,expected', [('Strict', 'strict'), ('LAX', 'lax'), ('none', 'none'), ('None ', 'none'),
                                          ('Foo', 'invalid'), ('', 'invalid'), ('Lax Strict', 'invalid')])
def test_samesite_values(raw, expected):
    assert parse_set_cookie(f'a=b; SameSite={raw}').samesite == expected


def test_absent_samesite_is_none_not_invalid():
    assert parse_set_cookie('a=b; Secure').samesite is None
    assert parse_set_cookie('a=b; SameSite').samesite == 'invalid'          # attribute present but valueless


def test_duplicate_attributes_last_one_wins_and_a_conflict_is_recorded():
    c = parse_set_cookie('a=b; SameSite=None; SameSite=Strict; Domain=x.test; Domain=y.test; Path=/a; Path=/b')
    assert (c.samesite, c.domain, c.path) == ('strict', 'y.test', '/b')
    assert c.conflicts == ('domain', 'path', 'samesite')


def test_repeating_an_attribute_with_the_same_value_is_not_a_conflict():
    c = parse_set_cookie('a=b; SameSite=Lax; samesite=LAX; Path=/; Path=/; Secure; Secure')
    assert c.conflicts == () and c.samesite == 'lax' and c.secure


def test_invalid_path_resets_to_the_default_path_even_after_a_valid_one():
    assert parse_set_cookie('a=b; Path=/x; Path=nope').path is None
    assert parse_set_cookie('a=b; Path=').path is None
    assert parse_set_cookie('a=b; Path=relative').path is None


@pytest.mark.parametrize('domain', ['', '.', '..'])
def test_empty_domain_is_ignored(domain):
    assert parse_set_cookie(f'a=b; Domain={domain}').domain is None


@pytest.mark.parametrize('header', ['novalue', '=x', '', ' = ', 'a=b\r\nSet-Cookie: x=y', 'a=b\x00', 'a' * 9000 + '=b', None, 123])
def test_unusable_headers_are_ignored_not_raised(header):
    assert parse_set_cookie(header) is None


@pytest.mark.parametrize('attrs,deleted', [
    ('Max-Age=0', True), ('Max-Age=-5', True), ('Max-Age=3600', False), ('Max-Age=abc', False),
    ('Expires=Thu, 01 Jan 1970 00:00:00 GMT', True), ('Expires=Wed, 01 Jan 2099 00:00:00 GMT', False),
    ('Expires=not a date', False),
    ('Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT', False),           # Max-Age takes precedence
    ('Max-Age=0; Expires=Wed, 01 Jan 2099 00:00:00 GMT', True),
    ('', False)])
def test_cookie_deletion_detection(attrs, deleted):
    assert parse_set_cookie(f'a=b; {attrs}', now=NOW).deleted is deleted


# ================================================================ name classification
@pytest.mark.parametrize('name', ['sessionid', 'PHPSESSID', 'JSESSIONID', 'connect.sid', 'sid', 'auth', 'authToken', 'oauth',
                                  'access_token', 'jwt', 'login', 'remember_me', 'passwd', 'api_key', 'SSO', 'ASP.NET_SessionId',
                                  '__Host-session', '__Secure-token'])
def test_session_like_names(name):
    assert is_session_like(name)


@pytest.mark.parametrize('name', ['theme', 'lang', 'author', '_ga', 'consent', 'sidebar', 'inside', 'residual', 'csrftoken',
                                  'XSRF-TOKEN', '_csrf', '__Host-csrf', '__RequestVerificationToken', 'anti-forgery'])
def test_non_session_names_including_anti_csrf(name):
    assert not is_session_like(name)


def test_prefix_helpers():
    assert prefix_kind('__Host-a') == prefix_kind('__HOST-a') == '__host-' and prefix_kind('__secure-a') == '__secure-'
    assert prefix_kind('__Host') is None and prefix_kind('x__Host-a') is None and prefix_kind('a') is None
    assert prefix_is_exact('__Host-a') and prefix_is_exact('__Secure-a')
    assert not prefix_is_exact('__host-a') and not prefix_is_exact('__SECURE-a')


@pytest.mark.parametrize('host,trusted', [('localhost', True), ('LOCALHOST', True), ('app.localhost', True), ('127.0.0.1', True),
                                          ('127.9.9.9', True), ('[::1]', True), ('::1', True), ('lab.test', False),
                                          ('10.0.0.5', False), ('notlocalhost', False), ('localhost.evil.test', False), (None, False)])
def test_trustworthy_hosts(host, trusted):
    assert is_trustworthy_host(host) is trusted


# ================================================================ Secure
def test_https_cookie_without_secure_is_flagged():
    f = only(cookies('https://a.test/', 'theme=dark; HttpOnly; SameSite=Lax'), 'COOKIE-NO-SECURE')
    assert f.confidence == 'Confirmed' and 'HTTPS' in f.evidence and f.extra['cookie_name'] == 'theme'


@pytest.mark.parametrize('header', ['theme=dark; Secure; HttpOnly; SameSite=Lax', 'theme=dark; SECURE; HttpOnly; SameSite=Strict',
                                    'theme=dark; secure=; HttpOnly; SameSite=None'])
def test_https_cookie_with_secure_has_no_findings(header):
    assert cookies('https://a.test/', header) == []


def test_secure_is_not_demanded_over_plain_http():
    """A Secure cookie from an insecure origin is rejected by browsers, so advising it there would break the cookie."""
    assert cookies('http://a.test/', 'theme=dark; HttpOnly; SameSite=Lax') == []
    assert 'COOKIE-NO-SECURE' not in rules(cookies('http://a.test/', 'sessionid=1; Path=/'))


def test_session_like_cookie_over_http_is_reported_as_a_potential_transport_issue():
    f = only(cookies('http://a.test/', 'sessionid=1; HttpOnly; SameSite=Lax'), 'COOKIE-SENSITIVE-OVER-HTTP')
    assert f.confidence == 'Potential' and 'heuristic' in f.evidence and f.severity == 'Medium'


def test_ordinary_cookie_over_http_is_not_a_transport_issue():
    assert 'COOKIE-SENSITIVE-OVER-HTTP' not in rules(cookies('http://a.test/', 'theme=dark'))


@pytest.mark.parametrize('url', ['http://localhost:8000/', 'http://127.0.0.1/', 'http://[::1]:8080/', 'http://app.localhost/'])
def test_loopback_http_is_a_trustworthy_origin_and_not_flagged(url):
    assert cookies(url, 'sessionid=1; HttpOnly; SameSite=Lax') == []


def test_other_lab_hostnames_over_http_are_still_flagged():
    assert 'COOKIE-SENSITIVE-OVER-HTTP' in rules(cookies('http://lab.test:8080/', 'sessionid=1; HttpOnly; SameSite=Lax'))


def test_https_is_judged_from_the_response_url_scheme():
    both = detect(resp('https://a.test/s', ['theme=1; HttpOnly; SameSite=Lax']), resp('http://a.test/p', ['theme=1; HttpOnly; SameSite=Lax']))
    f = only(both, 'COOKIE-NO-SECURE')
    assert [u for u in f.affected_urls] == ['https://a.test/s']


# ================================================================ HttpOnly
def test_missing_httponly_is_flagged_and_present_is_not():
    f = only(cookies('https://a.test/', 'theme=dark; Secure; SameSite=Lax'), 'COOKIE-NO-HTTPONLY')
    assert 'HttpOnly' in f.evidence and f.confidence == 'Confirmed'
    assert cookies('https://a.test/', 'theme=dark; Secure; HttpOnly; SameSite=Lax') == []


CSRF_CONVENTIONAL = ['csrftoken', 'XSRF-TOKEN', 'xsrf-token', 'CSRFTOKEN']
CSRF_GENERIC = ['_csrf', 'CSRF-Secret', 'csrf_session_key', '__RequestVerificationToken', 'anti-forgery', 'my-xsrf-cookie']


def test_csrf_kind_classification():
    assert [csrf_kind(n) for n in CSRF_CONVENTIONAL] == ['conventional'] * len(CSRF_CONVENTIONAL)
    assert [csrf_kind(n) for n in CSRF_GENERIC] == ['generic'] * len(CSRF_GENERIC)
    assert csrf_kind('sessionid') is None and csrf_kind('theme') is None
    assert csrf_kind('__Host-csrftoken') == 'conventional' and csrf_kind('__Secure-_csrf') == 'generic'   # prefix is ignored


@pytest.mark.parametrize('name', CSRF_CONVENTIONAL)
def test_conventionally_script_readable_csrf_cookies_are_an_informational_observation_not_skipped(name):
    """Angular/Laravel (XSRF-TOKEN) and Django (csrftoken) keep these readable on purpose, so it is not a weakness."""
    f = only(cookies('https://a.test/', f'{name}=x; Secure; SameSite=Lax'), 'COOKIE-NO-HTTPONLY')
    assert f.confidence == 'Informational' and f.severity == 'Informational'
    assert 'convention' in f.evidence and 'JavaScript' in f.evidence and 'rather than a weakness by itself' in f.evidence


@pytest.mark.parametrize('name', CSRF_GENERIC)
def test_other_csrf_named_cookies_may_not_need_script_access_and_are_reported_as_potential(name):
    """Some designs (double-submit) need JavaScript access and others do not: a passive scan cannot tell."""
    f = only(cookies('https://a.test/', f'{name}=x; Secure; SameSite=Lax'), 'COOKIE-NO-HTTPONLY')
    assert f.confidence == 'Potential' and f.severity == 'Low'
    assert 'anti-CSRF' in f.evidence and 'cannot tell' in f.evidence and 'double-submit' in f.evidence


@pytest.mark.parametrize('name', CSRF_CONVENTIONAL + CSRF_GENERIC)
def test_csrf_cookies_with_httponly_are_not_reported_and_never_reported_as_session_like(name):
    assert cookies('https://a.test/', f'{name}=x; Secure; HttpOnly; SameSite=Lax') == []
    assert not is_session_like(name)


@pytest.mark.parametrize('name', CSRF_CONVENTIONAL + CSRF_GENERIC)
def test_csrf_named_cookies_still_get_every_other_check(name):
    found = cookies('https://a.test/', f'{name}=x; HttpOnly')
    assert {'COOKIE-NO-SECURE', 'COOKIE-SAMESITE-MISSING'} <= rules(found)


def test_ordinary_cookies_keep_the_confirmed_httponly_finding():
    f = only(cookies('https://a.test/', 'sessionid=x; Secure; SameSite=Lax'), 'COOKIE-NO-HTTPONLY')
    assert f.confidence == 'Confirmed' and f.severity == 'Medium'


def test_httponly_explanation_does_not_claim_it_stops_xss():
    f = only(cookies('https://a.test/', 'sessionid=x; Secure; SameSite=Lax'), 'COOKIE-NO-HTTPONLY')
    text = f' {f.description} {f.impact} {f.remediation} {f.evidence} '.lower()
    assert 'does not prevent cross-site scripting' in text
    assert not re.search(r'(?<!not )(prevents?|stops?|protects? (against|from)) (all |any )?(xss|cross-site scripting)', text)


# ================================================================ SameSite
def test_missing_samesite_is_flagged():
    f = only(cookies('https://a.test/', 'theme=dark; Secure; HttpOnly'), 'COOKIE-SAMESITE-MISSING')
    assert 'no SameSite' in f.evidence


@pytest.mark.parametrize('value', ['Strict', 'Lax', 'lax', 'LAX', 'STRICT'])
def test_valid_samesite_values_are_not_flagged(value):
    assert cookies('https://a.test/', f'sessionid=x; Secure; HttpOnly; SameSite={value}') == []


@pytest.mark.parametrize('value', ['Foo', '', 'Lax Strict', 'true'])
def test_invalid_samesite_value_is_flagged_as_unrecognized(value):
    f = only(cookies('https://a.test/', f'theme=x; Secure; HttpOnly; SameSite={value}'), 'COOKIE-SAMESITE-MISSING')
    assert 'unrecognized' in f.evidence


def test_samesite_none_without_secure_is_a_misconfiguration():
    found = cookies('https://a.test/', 'theme=x; HttpOnly; SameSite=None')
    f = only(found, 'COOKIE-SAMESITE-NONE-INSECURE')
    assert f.confidence == 'Confirmed' and 'without Secure' in f.evidence
    assert 'COOKIE-SAMESITE-NONE' not in rules(found) and 'COOKIE-SAMESITE-MISSING' not in rules(found)


def test_samesite_none_without_secure_is_flagged_even_over_http_and_for_ordinary_names():
    assert 'COOKIE-SAMESITE-NONE-INSECURE' in rules(cookies('http://a.test/', 'theme=x; HttpOnly; SameSite=None'))


def test_samesite_none_with_secure_is_valid_for_ordinary_cookies():
    assert cookies('https://a.test/', 'theme=x; Secure; HttpOnly; SameSite=None') == []


def test_samesite_none_with_secure_on_a_session_like_cookie_is_only_a_potential_finding():
    f = only(cookies('https://a.test/', 'sessionid=x; Secure; HttpOnly; SameSite=None'), 'COOKIE-SAMESITE-NONE')
    assert f.confidence == 'Potential' and 'heuristic' in f.evidence


def test_conflicting_samesite_values_follow_the_last_one():
    assert cookies('https://a.test/', 'sessionid=x; Secure; HttpOnly; SameSite=None; SameSite=Lax') == []
    f = only(cookies('https://a.test/', 'sessionid=x; Secure; HttpOnly; SameSite=Lax; SameSite=None'), 'COOKIE-SAMESITE-NONE')
    assert 'repeats samesite with different values' in f.evidence


@pytest.mark.parametrize('header', [
    '__Host-sid=1; Secure; HttpOnly; Path=/; SameSite=Strict', '__Secure-id=1; Secure; HttpOnly; SameSite=Lax',
    'sessionid=1; Secure; HttpOnly; SameSite=Lax', 'sessionid=1; Secure; HttpOnly; SameSite=Lax; Path=/app',
    'theme=1; Secure; HttpOnly; SameSite=None', 'csrftoken=1; Secure; HttpOnly; SameSite=Strict'])
def test_correctly_configured_cookies_produce_no_findings(header):
    assert cookies('https://a.test/', header) == []


# ================================================================ prefixes
@pytest.mark.parametrize('header', ['__Secure-a=1; Secure; HttpOnly; SameSite=Lax',
                                    '__Secure-a=1; Secure; HttpOnly; SameSite=Lax; Domain=a.test; Path=/x',
                                    '__Host-a=1; Secure; HttpOnly; SameSite=Lax; Path=/',
                                    '__HOST-a=1; Secure; HttpOnly; SameSite=Lax; Path=/'])
def test_valid_prefixed_cookies_are_not_flagged(header):
    assert 'COOKIE-PREFIX-INVALID' not in rules(cookies('https://a.test/', header))


@pytest.mark.parametrize('header,reason', [
    ('__Secure-a=1; HttpOnly; SameSite=Lax', 'does not set Secure'),
    ('__Host-a=1; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=a.test', 'sets a Domain attribute'),
    ('__Host-a=1; Secure; HttpOnly; SameSite=Lax', 'no valid Path attribute'),
    ('__Host-a=1; Secure; HttpOnly; SameSite=Lax; Path=app', 'no valid Path attribute'),
    ('__Host-a=1; Secure; HttpOnly; SameSite=Lax; Path=/app', 'Path other than /'),
    ('__Host-a=1; HttpOnly; SameSite=Lax; Path=/', 'does not set Secure')])
def test_prefix_requirements_are_enforced(header, reason):
    f = only(cookies('https://a.test/', header), 'COOKIE-PREFIX-INVALID')
    assert reason in f.evidence and f.confidence == 'Confirmed'
    assert 'prefix' in f.evidence and f.severity == 'Low'


def test_host_prefix_reports_every_violation_at_once():
    f = only(cookies('https://a.test/', '__Host-a=1; Domain=a.test; Path=/x'), 'COOKIE-PREFIX-INVALID')
    for part in ('does not set Secure', 'sets a Domain attribute', 'Path other than /'):
        assert part in f.evidence


def test_missing_secure_on_a_prefixed_cookie_is_not_reported_twice():
    found = cookies('https://a.test/', '__Secure-a=1; HttpOnly; SameSite=Lax')
    assert rules(found) == {'COOKIE-PREFIX-INVALID'}                      # not also COOKIE-NO-SECURE


def test_secure_prefix_over_plain_http_is_invalid_but_loopback_is_trustworthy():
    f = only(cookies('http://a.test/', '__Secure-a=1; Secure; HttpOnly; SameSite=Lax'), 'COOKIE-PREFIX-INVALID')
    assert 'plain HTTP' in f.evidence
    assert 'COOKIE-PREFIX-INVALID' not in rules(cookies('http://localhost:8000/', '__Secure-a=1; Secure; HttpOnly; SameSite=Lax'))


def test_non_canonical_prefix_case_is_only_a_potential_finding_with_hedged_wording():
    f = only(cookies('https://a.test/', '__host-a=1; Secure; HttpOnly; SameSite=Lax; Domain=a.test; Path=/'), 'COOKIE-PREFIX-INVALID')
    assert f.confidence == 'Potential' and 'different letter case' in f.evidence and 'case-insensitively' in f.evidence
    assert 'reject' not in f.evidence                                       # no claim about what a browser does


def test_non_canonical_prefix_without_secure_still_reports_missing_secure_separately():
    found = cookies('https://a.test/', '__secure-a=1; HttpOnly; SameSite=Lax')
    assert rules(found) == {'COOKIE-PREFIX-INVALID', 'COOKIE-NO-SECURE'}


@pytest.mark.parametrize('name', ['__Host', 'x__Host-a', '_Host-a', '__Hostile'])
def test_names_that_are_not_prefixes_get_no_prefix_findings(name):
    assert 'COOKIE-PREFIX-INVALID' not in rules(cookies('https://a.test/', f'{name}=1; Secure; HttpOnly; SameSite=Lax'))


def test_prefix_is_ignored_when_judging_whether_a_name_is_session_like():
    f = only(cookies('https://a.test/', '__Secure-sessionid=1; HttpOnly; SameSite=Lax'), 'COOKIE-PREFIX-INVALID')
    assert f.extra['session_like_name'] is True


# ================================================================ scope
def test_domain_on_a_session_like_cookie_is_a_potential_scope_finding():
    f = only(cookies('https://www.a.test/', f'sessionid=1; {HARD}; Domain=a.test'), 'COOKIE-BROAD-DOMAIN')
    assert f.confidence == 'Potential' and 'every subdomain of a.test' in f.evidence and 'heuristic' in f.evidence


def test_leading_dot_and_exact_host_domain_are_equally_judged():
    for domain in ('.a.test', 'a.test', 'A.TEST'):
        assert 'COOKIE-BROAD-DOMAIN' in rules(cookies('https://a.test/', f'sessionid=1; {HARD}; Domain={domain}'))


def test_domain_on_an_ordinary_cookie_is_not_flagged():
    assert cookies('https://www.a.test/', f'theme=1; {HARD}; Domain=a.test') == []


def test_parent_domain_cookies_are_not_automatically_vulnerable():
    """Only session-like cookies are reported, and only as Potential: a parent-domain cookie alone proves nothing."""
    for f in cookies('https://www.a.test/', f'sessionid=1; {HARD}; Domain=a.test'):
        assert f.confidence == 'Potential' and f.severity in ('Low', 'Informational')


@pytest.mark.parametrize('url,domain', [('https://93.184.216.34/', '93.184.216.34'), ('https://a.test/', 'other.test'),
                                        ('https://a.test/', 'evil-a.test'), ('https://[::1]/', '::1')])
def test_domain_that_is_an_ip_or_does_not_match_the_host_is_not_flagged(url, domain):
    assert 'COOKIE-BROAD-DOMAIN' not in rules(cookies(url, f'sessionid=1; {HARD}; Domain={domain}'))


@pytest.mark.parametrize('path', ['/', '/admin', '/a/b', 'relative'])
def test_path_is_never_flagged_because_it_is_not_a_security_boundary(path):
    assert cookies('https://a.test/', f'sessionid=1; {HARD}; Path={path}') == []


def test_host_prefixed_cookie_with_domain_is_a_prefix_issue_not_a_scope_issue():
    found = cookies('https://a.test/', f'__Host-sessionid=1; {HARD}; Path=/; Domain=a.test')
    assert rules(found) == {'COOKIE-PREFIX-INVALID'}


def test_conflicting_domain_values_follow_the_last_one_and_are_noted():
    f = only(cookies('https://a.test/', f'sessionid=1; {HARD}; Domain=other.test; Domain=a.test'), 'COOKIE-BROAD-DOMAIN')
    assert 'repeats domain with different values' in f.evidence


# ================================================================ severity
def test_ordinary_names_are_rated_one_likelihood_step_lower():
    session = cookies('https://a.test/', 'sessionid=1')
    ordinary = cookies('https://a.test/', 'theme=1')
    for rule, s_sev, o_sev in (('COOKIE-NO-SECURE', 'Medium', 'Low'), ('COOKIE-NO-HTTPONLY', 'Medium', 'Low'),
                               ('COOKIE-SAMESITE-MISSING', 'Low', 'Informational')):
        assert only(session, rule).severity == s_sev and only(ordinary, rule).severity == o_sev
    assert only(ordinary, 'COOKIE-NO-SECURE').extra['likelihood'] == 'Low'
    assert only(session, 'COOKIE-NO-SECURE').extra['likelihood'] == 'Medium'


def test_the_name_heuristic_never_decides_whether_a_missing_attribute_is_reported():
    assert {'COOKIE-NO-SECURE', 'COOKIE-NO-HTTPONLY', 'COOKIE-SAMESITE-MISSING'} <= rules(cookies('https://a.test/', 'theme=1'))


def test_no_cvss_in_serialized_cookie_findings():
    for f in cookies('https://a.test/', 'sessionid=1; SameSite=None'):
        assert not any('cvss' in key.lower() for key in f.to_dict())


# ================================================================ multiple cookies, aggregation, limits
def test_every_set_cookie_header_of_a_response_is_judged():
    found = cookies('https://a.test/', 'a=1; Secure; HttpOnly; SameSite=Lax', 'b=2; HttpOnly; SameSite=Lax',
                    'c=3; Secure; SameSite=Lax', 'd=4; Secure; HttpOnly')
    assert names(found, 'COOKIE-NO-SECURE') == ['b'] and names(found, 'COOKIE-NO-HTTPONLY') == ['c']
    assert names(found, 'COOKIE-SAMESITE-MISSING') == ['d'] and len(found) == 3


def test_header_name_case_does_not_matter_and_other_headers_are_ignored():
    found = detect(resp('https://a.test/', ['a=1'], header_name='set-cookie',
                        extra_headers=[('Cookie', 'x=1'), ('Set-Cookie2', 'y=1'), ('X-Set-Cookie', 'z=1')]))
    assert {f.extra['cookie_name'] for f in found} == {'a'}


def test_same_cookie_on_several_pages_is_one_finding_listing_every_page():
    found = detect(resp('https://a.test/', ['theme=1; Secure; HttpOnly']), resp('https://a.test/b', ['theme=1; Secure; HttpOnly']),
                   resp('https://a.test/c', ['theme=1; Secure; HttpOnly; SameSite=Lax']))
    f = only(found, 'COOKIE-SAMESITE-MISSING')
    assert f.affected_urls == ['https://a.test/', 'https://a.test/b'] and '2 pages set the cookie this way' in f.evidence


def test_a_cookie_secure_on_one_page_and_not_on_another_lists_only_the_weak_page():
    found = detect(resp('https://a.test/ok', ['theme=1; ' + HARD]), resp('https://a.test/weak', ['theme=1; HttpOnly; SameSite=Lax']))
    assert only(found, 'COOKIE-NO-SECURE').affected_urls == ['https://a.test/weak']


def test_different_cookie_names_get_distinct_findings_and_fingerprints():
    found = cookies('https://a.test/', 'a=1; HttpOnly; SameSite=Lax', 'b=1; HttpOnly; SameSite=Lax')
    assert sorted(f.rule_id for f in found) == ['COOKIE-NO-SECURE#a', 'COOKIE-NO-SECURE#b']
    assert len({f.fingerprint() for f in found}) == 2


def test_findings_are_deterministic():
    runs = [[(f.rule_id, f.severity, f.evidence) for f in cookies('https://a.test/', 'x=1', 'sessionid=2', 'y=3; Secure')] for _ in range(3)]
    assert runs[0] == runs[1] == runs[2]


def test_deleted_cookies_are_not_issued_and_are_skipped():
    assert cookies('https://a.test/', 'sessionid=; Max-Age=0', 'sid=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT') == []


def test_one_malformed_cookie_does_not_hide_the_others():
    found = cookies('https://a.test/', 'garbage', '=nameless', 'a=1\r\nx', 'b=1; HttpOnly; SameSite=Lax')
    assert names(found, 'COOKIE-NO-SECURE') == ['b']


def test_response_without_cookies_or_with_odd_headers_is_fine():
    """Responses with no Set-Cookie, or only unrelated headers, are normal data. (A header_all that RAISES is a bug,
    and is deliberately not swallowed: see test_an_error_reading_the_headers_is_not_swallowed.)"""
    ok = resp('https://a.test/x', ['theme=1; ' + HARD])
    odd = resp('https://a.test/y', [], extra_headers=[('X-Set-Cookie', 'a=1'), ('Set-Cookie-Extra', 'b=1'), ('', ''), ('SET-COOKIE', 'sessionid=1; ' + HARD)])
    assert detect(resp('https://a.test/'), ok) == []
    assert detect(odd) == []                                  # header names match case-insensitively and exactly; nothing to report here


def test_only_the_first_cookies_of_a_response_are_examined_and_findings_per_rule_are_bounded():
    found = cookies('https://a.test/', *[f'c{i}=1; HttpOnly; SameSite=Lax' for i in range(MAX_COOKIES_PER_RESPONSE + 50)])
    shown = names(found, 'COOKIE-NO-SECURE')
    assert len(shown) == MAX_NAMES_PER_RULE
    assert f'{MAX_COOKIES_PER_RESPONSE - MAX_NAMES_PER_RULE} more cookie name(s) have the same issue' in found[0].evidence
    assert all(int(n[1:]) < MAX_COOKIES_PER_RESPONSE for n in shown)


def test_session_like_cookies_are_listed_before_ordinary_ones_when_the_bound_applies():
    headers = [f'c{i}=1; HttpOnly; SameSite=Lax' for i in range(40)] + ['sessionid=1; HttpOnly; SameSite=Lax']
    found = cookies('https://a.test/', *headers)
    assert 'sessionid' in names(found, 'COOKIE-NO-SECURE') and len(names(found, 'COOKIE-NO-SECURE')) == MAX_NAMES_PER_RULE


# ================================================================ names shown to the user
def test_display_name_masks_identifier_runs_and_bounds_length():
    assert display_name('session_0123456789abcdef0123456789') == 'session_[id]'
    assert display_name('theme') == 'theme' and display_name('a\x01b c') == 'a?b?c'
    long = display_name('n' * 500)
    assert len(long) == MAX_NAME_CHARS and long.endswith('…')


def test_cookie_names_that_embed_an_identifier_are_masked_in_findings_and_merge():
    found = detect(resp('https://a.test/a', ['sess_0123456789abcdef0123456789=1; HttpOnly; SameSite=Lax']),
                   resp('https://a.test/b', ['sess_9876543210fedcba9876543210=1; HttpOnly; SameSite=Lax']))
    f = only(found, 'COOKIE-NO-SECURE')
    assert f.extra['cookie_name'] == 'sess_[id]' and len(f.affected_urls) == 2
    assert '0123456789abcdef' not in json.dumps(f.to_dict()) and '9876543210fedcba' not in repr(found)


@pytest.mark.parametrize('name', ['a' * 8000, '1 ' * 3000, '-' * 8000, 'a.' * 4000 + '@x'],
                         ids=['letters', 'digits-and-spaces', 'dashes', 'dots-and-at'])
def test_hostile_cookie_names_cannot_make_the_detector_burn_cpu(name):
    """
    Regression: the shared redaction patterns backtrack quadratically on long names (about 50 ms per 8 KB name, so
    seconds per page of hostile headers). Names are therefore cut to MAX_PARSED_NAME before any regex runs.
    """
    assert len(parse_set_cookie(f'{name}=1').name) <= MAX_PARSED_NAME
    started = time.perf_counter()
    pages = [resp(f'https://a.test/{i}', [f'{name}=1'] * MAX_COOKIES_PER_RESPONSE) for i in range(5)]
    found = detect(*pages)
    assert time.perf_counter() - started < 3.0 and found                      # was 25 s before the bound
    assert all(len(f.extra['cookie_name']) <= MAX_NAME_CHARS for f in found)


# ================================================================ value redaction (the central guarantee)
VALUES = ['SECRETVALUE0123', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij', 'user.name@example.com',
          'password=hunter2xyz', 'bearer abcdefghijklmnop', 'AKIAABCDEFGHIJKLMNOP', '4111111111111111', 'a1b2c3d4e5f6a7b8c9d0e1f2']
LEAK_FRAGMENTS = ['SECRETVALUE0123', 'eyJhbGciOiJIUzI1NiJ9', 'user.name', 'hunter2xyz', 'abcdefghijklmnop', 'AKIAABCDEFGHIJKLMNOP',
                  '4111111111111111', 'a1b2c3d4e5f6']


def assert_no_value(text, where):
    for fragment in LEAK_FRAGMENTS:
        assert fragment not in text, f'{fragment!r} leaked through {where}'


def awful_cookies(url):
    out = []
    for i, value in enumerate(VALUES):
        out += cookies(url, f'sessionid{i}={value}', f'theme{i}={value}; SameSite=None', f'__Host-x{i}={value}; Domain=a.test',
                       f'tok{i}={value}; Domain=a.test; SameSite=Foo')
    return out


@pytest.mark.parametrize('url', ['https://a.test/', 'http://a.test/', 'http://localhost/'])
def test_cookie_values_never_appear_in_any_field_or_representation(url):
    found = awful_cookies(url)
    assert len(found) > 20
    for f in found:
        blob = ' '.join([f.title, f.description, f.evidence, f.impact, f.remediation, f.reference, f.detection_method,
                         f.rule_id, json.dumps(f.extra, default=str), json.dumps(f.to_dict()), repr(f), str(f), f'{f}',
                         ' '.join(f.display_urls)])
        assert_no_value(blob, f.rule_id)
    assert_no_value(repr(found) + str([f.to_dict() for f in found]) + str(dict(enumerate(found))), 'containers')


def test_cookie_values_do_not_reach_logs_or_stdout(caplog, capsys):
    logger = logging.getLogger('cookie-test')
    with caplog.at_level(logging.DEBUG):
        for f in awful_cookies('https://a.test/'):
            logger.info('finding %s', f)
            logger.info('finding %r / %s', f, f.to_dict())
            print(f, f.to_dict())
    assert_no_value(caplog.text, 'logging')
    assert_no_value(capsys.readouterr().out, 'print')


def test_values_with_separators_or_quotes_cannot_smuggle_text_into_findings():
    found = cookies('https://a.test/', 'a="SECRETVALUE0123; Path=/"; HttpOnly', 'b=SECRETVALUE0123\t; HttpOnly')
    assert found and 'SECRETVALUE0123' not in json.dumps([f.to_dict() for f in found], default=str) + repr(found)


def test_url_secrets_are_sanitized_in_cookie_evidence_and_serialization():
    url = 'https://u:pw123@a.test/p;jsessionid=PATHSEC?sig=QUERYSEC&token=TOKSEC#FRAGSEC'
    (f,) = [x for x in cookies(url, 'theme=1; HttpOnly; SameSite=Lax') if x.extra['rule'] == 'COOKIE-NO-SECURE']
    blob = f.evidence + json.dumps(f.to_dict()) + repr(f) + ' '.join(f.display_urls)
    for secret in ('PATHSEC', 'QUERYSEC', 'TOKSEC', 'FRAGSEC', 'pw123'):
        assert secret not in blob
    assert f.affected_urls == [url]                                         # raw page identity kept internally, as elsewhere


def test_detector_state_holds_no_values():
    """The detector object itself must not accumulate cookie data between runs."""
    d = CookieSecurityDetector()
    d.run(SimpleNamespace(pages=[Page('https://a.test/', 0, resp('https://a.test/', ['sessionid=SECRETVALUE0123']))],
                          client=None, target=None, config=None))
    assert 'SECRETVALUE0123' not in repr(vars(d)) and vars(d) == {}


# ================================================================ cookie name validation
@pytest.mark.parametrize('name', ['a', 'A-b_c.d', "!#$%&'*+-.^_`|~", 'a1', 'ASP.NET_SessionId', 'x' * MAX_PARSED_NAME])
def test_valid_cookie_tokens_including_special_characters_are_analyzed_normally(name):
    assert parse_set_cookie(f'{name}=1').name_problems == ()
    assert 'COOKIE-MALFORMED-NAME' not in rules(cookies('https://a.test/', f'{name}=1; HttpOnly; SameSite=Lax'))
    assert 'COOKIE-NO-SECURE' in rules(cookies('https://a.test/', f'{name}=1; HttpOnly; SameSite=Lax'))


MALFORMED = [('my cookie', 'spaces'), ('a b c', 'spaces'), ('a(b)', 'separator characters'), ('a@b', 'separator characters'),
             ('a,b', 'separator characters'), ('a:b', 'separator characters'), ('a"b', 'separator characters'),
             ('a/b', 'separator characters'), ('a[b]', 'separator characters'), ('a?b', 'separator characters'),
             ('a{b}', 'separator characters'), ('a<b>', 'separator characters'), ('a\\b', 'separator characters'),
             ('a\x01b', 'control characters'), ('a\x7fb', 'control characters'), ('a\tb', 'control characters'),
             ('é', 'non-ASCII characters'), ('a\u200bb', 'non-ASCII characters'), ('session id', 'spaces')]


@pytest.mark.parametrize('name,reason', MALFORMED, ids=[repr(n) for n, _ in MALFORMED])
def test_malformed_cookie_names_are_classified_not_given_ordinary_findings(name, reason):
    assert reason in parse_set_cookie(f'{name}=1').name_problems
    for url in ('https://a.test/', 'http://a.test/'):
        found = cookies(url, f'{name}=SECRETVALUE0123')                       # no attribute at all: would be 3+ findings
        f = only(found, 'COOKIE-MALFORMED-NAME')
        assert len(found) == 1 and f.confidence == 'Informational' and f.severity == 'Informational'
        assert reason in f.evidence and 'not analyzed' in f.evidence and 'SECRETVALUE0123' not in f.evidence
        assert f.evidence.isprintable() and f.extra['session_like_name'] is False
        assert f.extra['cookie_name'].isprintable() and all(ch not in f.extra['cookie_name'] for ch in '\x01\x7f\t\u200b')


def test_header_level_control_characters_are_ignored_outright():
    """CR, LF and NUL make the header itself unparseable (and are a header-injection signal): nothing is reported."""
    assert cookies('https://a.test/', 'a=1\r\nSet-Cookie: b=2', 'a\x00b=1', 'a=\x00') == []


def test_malformed_names_do_not_hide_valid_cookies_in_the_same_response():
    found = cookies('https://a.test/', 'bad name=1', 'good=1; HttpOnly; SameSite=Lax')
    assert names(found, 'COOKIE-MALFORMED-NAME') == ['bad?name'] and names(found, 'COOKIE-NO-SECURE') == ['good']


def test_the_same_malformed_name_on_several_pages_is_one_finding():
    found = detect(resp('https://a.test/a', ['bad name=1']), resp('https://a.test/b', ['bad name=1']))
    (f,) = found
    assert len(f.affected_urls) == 2 and '2 pages set the cookie this way' in f.evidence


def test_a_bad_character_beyond_the_parse_limit_is_still_detected():
    c = parse_set_cookie('n' * (MAX_PARSED_NAME + 50) + ' tail=1')
    assert c.name_problems == ('invalid characters',) and c.name_digest
    assert parse_set_cookie('n' * (MAX_PARSED_NAME + 50) + '=1').name_problems == ()


# ================================================================ session-like heuristic: whole words, never substrings
@pytest.mark.parametrize('name', [
    'assessment', 'assess', 'obsession', 'possession', 'concession', 'profession', 'recession', 'guess', 'sessionless',
    'author', 'authors', 'authority', 'authorize', 'unauthorized', 'tokenizer', 'tokenomics', 'secretary', 'secretive',
    'passage', 'passport', 'bypass', 'compass', 'loginfo', 'blogin', 'bearers', 'ssoup', 'sidebar', 'sidekick', 'inside',
    'residual', 'resident', 'consider', 'theme', 'lang', 'consent', '_ga', 'cart', 'user_prefs'])
def test_ordinary_names_containing_session_words_as_substrings_are_not_session_like(name):
    assert not is_session_like(name)


@pytest.mark.parametrize('name', [
    'session', 'SESSION', 'sess', 'sid', 'SID', 'sessionid2', 'sid1', 'my_session', 'userSession', 'session-12345', 'auth',
    'auth-token', 'AuthToken', 'authToken', 'oauth', 'access.token', 'access_token', 'refresh_token', 'api-key', 'apiKey',
    'ApiKey', 'remember_me', 'login', 'passwd', 'jwt', 'SSO', 'JSESSIONID', 'PHPSESSID', 'ASPSESSIONIDQQQSTRRT',
    'ASP.NET_SessionId', 'connect.sid', '__Host-session', '__Secure-token'])
def test_names_with_session_words_on_word_boundaries_are_session_like(name):
    assert is_session_like(name)


def test_a_false_positive_name_is_rated_as_an_ordinary_cookie():
    """'assessment' used to match 'sess' and was rated like a session cookie."""
    f = only(cookies('https://a.test/', 'assessment=1; HttpOnly; SameSite=Lax'), 'COOKIE-NO-SECURE')
    assert f.severity == 'Low' and f.extra['session_like_name'] is False
    assert not rules(cookies('https://a.test/', 'obsession=1; Secure; HttpOnly; SameSite=Lax; Domain=a.test'))


def test_the_name_heuristic_is_always_labelled_as_a_heuristic_never_as_proof():
    for header, session in (('sessionid=1', True), ('assessment=1', False)):
        for f in cookies('https://a.test/', header):
            if f.confidence != 'Confirmed' or f.extra['rule'] not in ('COOKIE-NO-SECURE', 'COOKIE-NO-HTTPONLY', 'COOKIE-SAMESITE-MISSING'):
                continue
            assert f.extra['session_like_name'] is session and 'name-based heuristic' in f.evidence
            assert ('treats the cookie as session-like' in f.evidence) is session
            assert 'not proof' in f.evidence or 'may still matter' in f.evidence
    for f in cookies('http://a.test/', 'sessionid=1; Domain=a.test', 'jwt=1; SameSite=None; Secure'):
        text = f' {f.evidence} {f.description} {f.title} '
        assert not re.search(r'\b(is|are) (a|the) session cookie', text)
        if f.extra['rule'] in ('COOKIE-SENSITIVE-OVER-HTTP', 'COOKIE-BROAD-DOMAIN', 'COOKIE-SAMESITE-NONE'):
            assert f.confidence == 'Potential' and 'heuristic' in f.evidence


# ================================================================ oversized / unusable Max-Age
INT_LIMIT = (sys.get_int_max_str_digits() if hasattr(sys, 'get_int_max_str_digits') else 0) or 4300
HUGE = '9' * (INT_LIMIT + 1)


def test_the_huge_value_really_exceeds_pythons_integer_conversion_limit():
    if hasattr(sys, 'get_int_max_str_digits') and sys.get_int_max_str_digits():
        with pytest.raises(ValueError):
            int(HUGE)                                                  # why this regression matters


def test_oversized_max_age_does_not_discard_the_cookie_or_its_other_attributes():
    c = parse_set_cookie(f'a=b; Max-Age={HUGE}; Secure; HttpOnly; SameSite=Strict; Domain=x.test; Path=/p', now=NOW)
    assert c is not None and c.deleted is False
    assert (c.secure, c.httponly, c.samesite, c.domain, c.path) == (True, True, 'strict', 'x.test', '/p')


def test_oversized_negative_max_age_means_expired_and_zeros_are_not_digits_of_a_big_number():
    assert parse_set_cookie(f'a=b; Max-Age=-{HUGE}', now=NOW).deleted is True
    assert parse_set_cookie(f'a=b; Max-Age={"0" * 5000}5', now=NOW).deleted is False
    assert parse_set_cookie(f'a=b; Max-Age={"0" * 5000}', now=NOW).deleted is True
    assert parse_set_cookie(f'a=b; Max-Age=-{"0" * 5000}', now=NOW).deleted is True


def test_max_age_parsing_is_total_and_clamped():
    assert _parse_max_age(HUGE) == 10 ** 18 and _parse_max_age('-' + HUGE) == -10 ** 18
    assert _parse_max_age('007') == 7 and _parse_max_age('-0') == 0 and _parse_max_age('3600') == 3600
    assert all(_parse_max_age(v) is None for v in ('', '-', '+5', '5.5', '1e5', 'abc', '\u0661\u0662\u0663', '5x', '- 5'))


@pytest.mark.parametrize('value', ['abc', '1e5', '+5', '5.5', '\u0661\u0662\u0663', ''])
def test_unusable_max_age_is_ignored_and_expires_still_applies(value):
    assert parse_set_cookie(f'a=b; Max-Age={value}', now=NOW).deleted is False
    assert parse_set_cookie(f'a=b; Max-Age={value}; Expires=Thu, 01 Jan 1970 00:00:00 GMT', now=NOW).deleted is True


def test_a_cookie_with_an_oversized_max_age_is_still_analyzed_by_the_detector():
    found = cookies('https://a.test/', f'theme=1; Max-Age={HUGE}', f'gone=1; Max-Age=-{HUGE}', 'other=1; HttpOnly; SameSite=Lax')
    assert names(found, 'COOKIE-NO-SECURE') == ['other', 'theme']             # 'gone' expired, 'other' unaffected
    assert names(found, 'COOKIE-NO-HTTPONLY') == ['theme'] and names(found, 'COOKIE-SAMESITE-MISSING') == ['theme']


# ================================================================ name truncation: identity and collisions
LONG = 'n' * (MAX_PARSED_NAME + 40)


def test_names_at_the_limit_have_no_digest_and_longer_ones_do():
    assert parse_set_cookie('x' * MAX_PARSED_NAME + '=1').name_digest is None
    c = parse_set_cookie('x' * (MAX_PARSED_NAME + 1) + '=1')
    assert len(c.name) == MAX_PARSED_NAME and re.fullmatch(f'[0-9a-f]{{{MAX_DIGEST_CHARS}}}', c.name_digest)


def test_long_names_that_differ_only_after_the_cut_stay_distinct():
    a, b = LONG + 'A', LONG + 'B'
    ca, cb = parse_set_cookie(f'{a}=1'), parse_set_cookie(f'{b}=1')
    assert ca.name == cb.name and ca.name_digest != cb.name_digest          # the cut alone would have merged them
    found = cookies('https://a.test/', f'{a}=1; HttpOnly; SameSite=Lax', f'{b}=1; HttpOnly; SameSite=Lax')
    pair = [f for f in found if f.extra['rule'] == 'COOKIE-NO-SECURE']
    assert len(pair) == 2 and len({f.rule_id for f in pair}) == 2 and len({f.fingerprint() for f in pair}) == 2
    assert len({f.extra['cookie_name'] for f in pair}) == 2
    assert all(len(f.extra['cookie_name']) <= MAX_NAME_CHARS and '…#' in f.extra['cookie_name'] for f in pair)


def test_the_same_long_name_on_two_pages_is_one_finding():
    found = detect(resp('https://a.test/a', [f'{LONG}=1; HttpOnly; SameSite=Lax']), resp('https://a.test/b', [f'{LONG}=2; HttpOnly; SameSite=Lax']))
    (f,) = [x for x in found if x.extra['rule'] == 'COOKIE-NO-SECURE']
    assert len(f.affected_urls) == 2                                          # the value differs; the identity does not


def test_a_long_name_never_collides_with_a_short_name_equal_to_its_first_chars():
    short = 'n' * MAX_PARSED_NAME
    found = cookies('https://a.test/', f'{short}=1; HttpOnly; SameSite=Lax', f'{short}x=1; HttpOnly; SameSite=Lax')
    assert len([f for f in found if f.extra['rule'] == 'COOKIE-NO-SECURE']) == 2


def test_digest_is_deterministic_and_the_raw_name_is_never_shown():
    secret_tail = 'SECRETTAILPART'
    name = 'visible_prefix_' + 'z' * 300 + secret_tail
    labels = {cookie_label(parse_set_cookie(f'{name}=1')) for _ in range(3)}
    assert len(labels) == 1
    found = cookies('https://a.test/', f'{name}=1')
    blob = ' '.join([repr(found), json.dumps([f.to_dict() for f in found]), *(f.evidence for f in found),
                     *(f.extra['cookie_name'] for f in found)])
    assert secret_tail not in blob and 'z' * 60 not in blob                    # only the first 40 characters can appear
    assert 'visible_prefix_' in blob
    assert 'z' * (MAX_LABEL_PREFIX + 1) not in blob                           # only the first MAX_LABEL_PREFIX characters can appear


def test_malformed_long_names_are_also_kept_distinct():
    a, b = LONG + ' A', LONG + ' B'
    found = cookies('https://a.test/', f'{a}=1', f'{b}=1')
    assert len(found) == 2 and {f.extra['rule'] for f in found} == {'COOKIE-MALFORMED-NAME'}


def test_identifier_masking_merges_only_what_it_is_meant_to_merge():
    """Per-user identifier runs (20+ alphanumerics with a digit) merge; everything else stays distinct."""
    def labels(*nm):
        return {f.extra['cookie_name'] for f in cookies('https://a.test/', *[f'{n}=1; HttpOnly; SameSite=Lax' for n in nm])
                if f.extra['rule'] == 'COOKIE-NO-SECURE'}
    assert len(labels('sess_' + 'a1' * 12, 'sess_' + 'b2' * 12)) == 1          # same cookie, different user id: merged
    assert len(labels('sess_' + 'a1' * 12, 'auth_' + 'a1' * 12)) == 2          # different cookie: distinct
    assert len(labels('x' + '1' * 18, 'x' + '2' * 18)) == 2                    # run shorter than 20: not masked
    assert len(labels('a' * 20, 'b' * 20)) == 2                                # no digit: not an identifier


def test_extra_records_the_cookie_label_not_a_raw_value():
    (f,) = [x for x in cookies('https://a.test/', f'{LONG}=SECRETVALUE0123; HttpOnly; SameSite=Lax') if x.extra['rule'] == 'COOKIE-NO-SECURE']
    assert 'SECRETVALUE0123' not in json.dumps(f.extra, default=str) and f.extra['cookie_name'].endswith(parse_set_cookie(f'{LONG}=1').name_digest)


# ================================================================ session-like: exact words, not word endings
@pytest.mark.parametrize('name', ['possession_id', 'possessionid', 'PossessionId', 'obsessionid', 'concessionid', 'professionid',
                                  'recessionid', 'wassessid', 'guessid', 'possessid', 'obsessid', 'processid', 'possession-id-2'])
def test_words_that_merely_end_in_session_or_sessid_are_not_session_ids(name):
    """Regression: endswith('sessionid') matched 'possessionid'/'obsessionid', and pairing 'possession'+'id' did too."""
    assert not is_session_like(name)


@pytest.mark.parametrize('name', ['session_id', 'sessionId', 'SessionID', 'session-id', 'sess_id', 'PHPSESSID', 'phpsessid_x', 'jsessionid',
                                  'JSESSIONID', 'ASPSESSIONIDQQQSTRRT', 'ASP.NET_SessionId', 'sessionid2', 'user_session', 'SID'])
def test_real_session_id_names_are_still_recognized(name):
    assert is_session_like(name)


def test_run_together_lowercase_session_ids_are_a_known_false_negative():
    """Trade-off, pinned on purpose: without a word boundary 'mysessionid' cannot be told from 'possessionid'.
    The cost is only a one-step lower rating; the missing attribute is still reported."""
    assert not is_session_like('mysessionid')
    assert 'COOKIE-NO-SECURE' in rules(cookies('https://a.test/', 'mysessionid=1; HttpOnly; SameSite=Lax'))


def test_a_former_suffix_false_positive_is_rated_as_an_ordinary_cookie():
    f = only(cookies('https://a.test/', 'possession_id=1; HttpOnly; SameSite=Lax'), 'COOKIE-NO-SECURE')
    assert f.severity == 'Low' and f.extra['session_like_name'] is False
    assert 'COOKIE-BROAD-DOMAIN' not in rules(cookies('https://www.a.test/', f'possession_id=1; {HARD}; Domain=a.test'))
    assert 'COOKIE-SENSITIVE-OVER-HTTP' not in rules(cookies('http://a.test/', 'possession_id=1; HttpOnly; SameSite=Lax'))


# ================================================================ digest strength
def test_digest_is_128_bits_and_every_label_fits_the_display_limit():
    assert MAX_DIGEST_CHARS == 32 and MAX_LABEL_PREFIX + len('…#') + MAX_DIGEST_CHARS <= MAX_NAME_CHARS
    c = parse_set_cookie('x' * (MAX_PARSED_NAME + 1) + '=1')
    assert re.fullmatch(r'[0-9a-f]{32}', c.name_digest) and len(cookie_label(c)) <= MAX_NAME_CHARS
    worst = parse_set_cookie('X1' * 200 + '=1')
    assert len(cookie_label(worst)) <= MAX_NAME_CHARS


def test_names_that_collided_under_the_old_32_bit_digest_stay_distinct():
    """
    Regression: with an 8-hex digest two attacker-chosen names collided after ~10^5 tries. These two did
    (n*300 + '61794' and n*300 + '100243'); a hostile server could use that to merge or hide a cookie.
    """
    a, b = 'n' * 300 + '61794', 'n' * 300 + '100243'
    da, db = (hashlib.sha256(x.encode()).hexdigest() for x in (a, b))
    assert da[:8] == db[:8] and da != db                                      # the old digest could not tell them apart
    ca, cb = parse_set_cookie(f'{a}=1'), parse_set_cookie(f'{b}=1')
    assert ca.name_digest != cb.name_digest and cookie_label(ca) != cookie_label(cb)
    found = [f for f in cookies('https://a.test/', f'{a}=1; HttpOnly; SameSite=Lax', f'{b}=1; HttpOnly; SameSite=Lax')
             if f.extra['rule'] == 'COOKIE-NO-SECURE']
    assert len(found) == 2 and len({f.fingerprint() for f in found}) == 2


# ================================================================ whitespace and case folding
NOT_TRIMMED = ['\u00a0', '\x0b', '\x0c', '\u2003', '\u3000', '\x85', '\u200b']


@pytest.mark.parametrize('ws', NOT_TRIMMED, ids=[hex(ord(w)) for w in NOT_TRIMMED])
def test_only_space_and_tab_are_trimmed_like_a_browser_does(ws):
    """str.strip() would also remove these; a browser keeps them, so the cookie it stores differs from a trimmed reading."""
    assert not parse_set_cookie(f'a=b; Secure{ws}').secure and not parse_set_cookie(f'a=b; HttpOnly{ws}').httponly
    assert not parse_set_cookie(f'a=b;{ws}Secure').secure
    assert parse_set_cookie(f'a=b; SameSite=Lax{ws}').samesite == 'invalid'
    assert parse_set_cookie(f'a=b; SameSite={ws}Lax').samesite == 'invalid'
    assert parse_set_cookie(f'a{ws}=1').name_problems and parse_set_cookie(f'{ws}a=1').name_problems


def test_an_attribute_with_unicode_whitespace_is_reported_as_missing():
    found = cookies('https://a.test/', 'sessionid=1; Secure\u00a0; HttpOnly\u00a0; SameSite=Lax')
    assert {'COOKIE-NO-SECURE', 'COOKIE-NO-HTTPONLY'} <= rules(found)         # the browser did not see Secure/HttpOnly either


@pytest.mark.parametrize('pad', ['', ' ', '\t', ' \t ', '\t\t'])
def test_space_and_tab_around_names_attributes_and_values_are_ignored(pad):
    c = parse_set_cookie(f'{pad}sessionid{pad}={pad}v{pad};{pad}Secure{pad};{pad}SameSite{pad}={pad}Lax{pad};{pad}Path{pad}={pad}/x{pad}')
    assert (c.name, c.secure, c.samesite, c.path, c.name_problems) == ('sessionid', True, 'lax', '/x', ())


def test_names_differing_only_by_space_or_tab_padding_are_the_same_cookie():
    found = detect(resp('https://a.test/a', [' a=1; HttpOnly; SameSite=Lax']), resp('https://a.test/b', ['a\t=1; HttpOnly; SameSite=Lax']))
    (f,) = [x for x in found if x.extra['rule'] == 'COOKIE-NO-SECURE']
    assert len(f.affected_urls) == 2 and f.extra['cookie_name'] == 'a'
    assert cookie_label(parse_set_cookie(f' {LONG}\t=1')) == cookie_label(parse_set_cookie(f'{LONG}=1'))   # trimmed before the digest


def test_unicode_whitespace_in_a_domain_value_is_not_trimmed_and_never_matches_the_host():
    assert cookies('https://a.test/', f'sessionid=1; {HARD}; Domain=\u00a0a.test') == []


def test_case_folding_is_ascii_only():
    assert csrf_kind('csrftoken') == 'conventional' and csrf_kind('CSRFTOKEN') == 'conventional'
    assert csrf_kind('csrfto\u212aen') == 'generic'                           # Kelvin sign is not 'k': not the conventional name
    assert prefix_kind('__Host-a') == '__host-' and prefix_kind('__\u017fecure-a') is None   # long s is not 's'
    assert parse_set_cookie('a=b; SAMESITE=LAX; SeCuRe').samesite == 'lax'
    assert rules(cookies('https://a.test/', 'csrfto\u212aen=1', '__\u017fecure-a=1')) == {'COOKIE-MALFORMED-NAME'}


# ================================================================ prefix letter case
HOST_SPELLINGS = ['__Host-', '__host-', '__HOST-', '__hOsT-']
SECURE_SPELLINGS = ['__Secure-', '__secure-', '__SECURE-', '__sEcUrE-']
ALL_SPELLINGS = HOST_SPELLINGS + SECURE_SPELLINGS


@pytest.mark.parametrize('prefix', ALL_SPELLINGS)
def test_a_prefixed_cookie_that_meets_every_requirement_is_fine_in_any_letter_case(prefix):
    assert 'COOKIE-PREFIX-INVALID' not in rules(cookies('https://a.test/', f'{prefix}a=1; {HARD}; Path=/'))


@pytest.mark.parametrize('prefix', ALL_SPELLINGS)
def test_prefix_without_secure_exact_case_is_confirmed_and_other_case_is_potential(prefix):
    found = cookies('https://a.test/', f'{prefix}a=1; HttpOnly; SameSite=Lax; Path=/')
    f = only(found, 'COOKIE-PREFIX-INVALID')
    if prefix in ('__Host-', '__Secure-'):
        assert f.confidence == 'Confirmed' and 'COOKIE-NO-SECURE' not in rules(found)     # reported once, as the prefix issue
        assert 'reject' in f.evidence and 'letter case' not in f.evidence
    else:
        assert f.confidence == 'Potential' and 'COOKIE-NO-SECURE' in rules(found)          # enforcement varies: also reported plainly
        assert 'different letter case' in f.evidence and 'differ between browsers and versions' in f.evidence
        assert 'reject' not in f.evidence                                                  # no claim about what a browser does


@pytest.mark.parametrize('prefix', HOST_SPELLINGS)
def test_host_prefix_domain_and_path_rules_follow_the_same_exact_versus_variant_split(prefix):
    exact = prefix == '__Host-'
    for header, reason in ((f'{prefix}a=1; {HARD}; Path=/; Domain=a.test', 'sets a Domain attribute'),
                           (f'{prefix}a=1; {HARD}; Path=/app', 'Path other than /'), (f'{prefix}a=1; {HARD}', 'no valid Path attribute')):
        f = only(cookies('https://a.test/', header), 'COOKIE-PREFIX-INVALID')
        assert reason in f.evidence and f.confidence == ('Confirmed' if exact else 'Potential')


@pytest.mark.parametrize('prefix', SECURE_SPELLINGS)
def test_secure_prefix_does_not_require_path_or_forbid_domain_in_any_letter_case(prefix):
    assert 'COOKIE-PREFIX-INVALID' not in rules(cookies('https://a.test/', f'{prefix}a=1; {HARD}; Domain=a.test; Path=/x'))


@pytest.mark.parametrize('name', ['__Host', '__Secure', '__Host_a', '__Securea', '_Host-a', 'Host-a', 'x__Secure-a', '__Hostile', '__Host\u2010a', '__\u017fecure-a'])
def test_near_misses_and_look_alikes_are_not_prefixes(name):
    assert prefix_kind(name) is None
    assert 'COOKIE-PREFIX-INVALID' not in rules(cookies('https://a.test/', f'{name}=1; HttpOnly; SameSite=Lax'))


def test_only_the_canonical_spellings_are_exact():
    assert [prefix_is_exact(f'{p}a') for p in ALL_SPELLINGS] == [True, False, False, False, True, False, False, False]


# ================================================================ cookies the browser would reject: no contradictory findings
def text_of(f):
    return f'{f.evidence} {f.description} {f.impact}'


def test_samesite_none_without_secure_on_https_is_reported_once_as_a_rejected_cookie():
    """Regression: COOKIE-NO-SECURE used to be added too, claiming browsers 'also send it over plain HTTP'."""
    found = cookies('https://a.test/', 'theme=1; HttpOnly; SameSite=None')
    assert rules(found) == {'COOKIE-SAMESITE-NONE-INSECURE'}
    f = only(found, 'COOKIE-SAMESITE-NONE-INSECURE')
    assert 'reject such a cookie' in f.evidence and 'not stored' in f.evidence and f.confidence == 'Confirmed'
    assert 'send it over plain HTTP' not in ' '.join(x.evidence for x in found)


@pytest.mark.parametrize('name', ['theme', 'sessionid'])
def test_samesite_none_without_secure_gets_no_missing_secure_finding_for_any_name(name):
    assert 'COOKIE-NO-SECURE' not in rules(cookies('https://a.test/', f'{name}=1; HttpOnly; SameSite=None'))


def test_the_none_insecure_evidence_describes_both_browser_behaviours_accurately():
    f = only(cookies('https://a.test/', 'theme=1; HttpOnly; SameSite=None'), 'COOKIE-SAMESITE-NONE-INSECURE')
    assert 'Browsers that follow the SameSite specification reject such a cookie' in f.evidence
    assert 'older browsers that accept it send it on cross-site requests, including over plain HTTP' in f.evidence


@pytest.mark.parametrize('header,expect_no_secure', [
    ('theme=1; HttpOnly; SameSite=Lax', True), ('theme=1; HttpOnly; SameSite=Strict', True), ('theme=1; HttpOnly', True),
    ('theme=1; HttpOnly; SameSite=Bogus', True),                                        # accepted: unspecified SameSite
    ('theme=1; HttpOnly; SameSite=None; SameSite=Lax', True),                           # last one wins: Lax is accepted
    ('theme=1; HttpOnly; SameSite=Lax; SameSite=None', False)])                         # last one wins: None is rejected
def test_missing_secure_is_still_reported_when_the_browser_would_accept_the_cookie(header, expect_no_secure):
    found = cookies('https://a.test/', header)
    assert ('COOKIE-NO-SECURE' in rules(found)) is expect_no_secure
    if expect_no_secure:
        assert 'also send it over plain HTTP' in only(found, 'COOKIE-NO-SECURE').evidence


def test_samesite_none_with_secure_is_unaffected_by_the_interaction():
    assert cookies('https://a.test/', 'theme=1; Secure; HttpOnly; SameSite=None') == []
    assert rules(cookies('https://a.test/', 'sessionid=1; Secure; HttpOnly; SameSite=None')) == {'COOKIE-SAMESITE-NONE'}


def test_samesite_none_without_secure_over_http_separates_rejection_header_exposure_and_later_sending():
    """Three different events: the browser rejects the cookie, the header crossed the wire, the cookie may be sent later."""
    found = cookies('http://a.test/', 'sessionid=1; HttpOnly; SameSite=None')
    assert rules(found) == {'COOKIE-SAMESITE-NONE-INSECURE', 'COOKIE-SENSITIVE-OVER-HTTP'}
    none = only(found, 'COOKIE-SAMESITE-NONE-INSECURE').evidence
    assert 'reject such a cookie' in none and 'not stored' in none                       # browser rejection
    assert 'Set-Cookie response header' in none and 'whether or not the browser stores the cookie' in none   # header exposure
    http = only(found, 'COOKIE-SENSITIVE-OVER-HTTP').evidence
    assert 'transmitted over plain HTTP' in http and 'whether or not the browser stores the cookie' in http
    assert 'reject the cookie (reported separately)' in http and 'depends on the browser' in http   # storage is not asserted
    assert 'browsers accept it' not in http and 'send it in clear text on later' not in http       # the later-send claim is absent


def test_samesite_none_over_http_for_an_ordinary_name_still_reports_the_rejection_and_the_header():
    found = cookies('http://a.test/', 'theme=x; HttpOnly; SameSite=None')
    assert rules(found) == {'COOKIE-SAMESITE-NONE-INSECURE'}
    assert 'transmitted over plain HTTP' in only(found, 'COOKIE-SAMESITE-NONE-INSECURE').evidence


def test_samesite_none_without_secure_on_https_makes_no_header_exposure_claim():
    f = only(cookies('https://a.test/', 'theme=1; HttpOnly; SameSite=None'), 'COOKIE-SAMESITE-NONE-INSECURE')
    assert 'transmitted over plain HTTP' not in f.evidence


def test_trustworthy_origin_makes_no_header_exposure_claim_for_samesite_none():
    found = cookies('http://localhost:8000/', 'sessionid=1; HttpOnly; SameSite=None')
    assert rules(found) == {'COOKIE-SAMESITE-NONE-INSECURE'} and 'transmitted over plain HTTP' not in found[0].evidence


# ---------------------------------------------------------------- Secure cookies over plain HTTP
def test_an_insecure_session_cookie_accepted_over_http_is_the_cleartext_finding():
    found = cookies('http://a.test/', 'sessionid=1; HttpOnly; SameSite=Lax')
    f = only(found, 'COOKIE-SENSITIVE-OVER-HTTP')
    assert 'COOKIE-SECURE-OVER-HTTP' not in rules(found) and f.confidence == 'Potential'
    assert 'no Secure attribute, so browsers accept it and send it in clear text on later requests' in f.evidence
    assert 'transmitted over plain HTTP' in f.evidence


def test_a_secure_cookie_over_untrusted_http_is_rejected_by_the_browser_but_its_header_was_still_exposed():
    """Regression: the evidence used to say the cookie 'cannot leak'. Rejection happens after the header was sent."""
    found = cookies('http://a.test/', f'sessionid=1; {HARD}')
    assert rules(found) == {'COOKIE-SECURE-OVER-HTTP'}                                 # and not COOKIE-SENSITIVE-OVER-HTTP
    f = only(found, 'COOKIE-SECURE-OVER-HTTP')
    assert f.confidence == 'Confirmed' and f.severity == 'Low'
    assert 'Set-Cookie response header, including the cookie value, was transmitted over plain HTTP' in f.evidence
    assert 'anyone able to observe that connection can read it' in f.evidence
    assert 'refuse to store a Secure cookie from an insecure origin' in f.evidence
    assert 'rejection does not protect the header that was already sent' in f.evidence
    assert 'trustworthy origins excepted' in f.evidence


FORBIDDEN_CLAIMS = ('cannot leak', 'cannot be intercepted', 'can not be intercepted', 'cannot be observed', 'cannot be read',
                    'not exposed', 'no exposure', 'is protected', 'is safe')


@pytest.mark.parametrize('url,header', [
    ('http://a.test/', f'sessionid=1; {HARD}'), ('http://a.test/', f'theme=1; {HARD}'),
    ('http://a.test/', 'sessionid=1; HttpOnly; SameSite=None'), ('http://a.test/', 'theme=1; HttpOnly; SameSite=None'),
    ('http://a.test/', 'sessionid=1; HttpOnly; SameSite=Lax'), ('http://a.test/', '__secure-sessionid=1; Secure; HttpOnly; SameSite=Lax'),
    ('http://a.test/', '__Secure-sessionid=1; Secure; HttpOnly; SameSite=Lax'), ('http://a.test/', '__Host-sessionid=1; Secure; HttpOnly; Path=/')])
def test_no_http_evidence_claims_that_browser_rejection_prevents_exposure(url, header):
    found = cookies(url, header)
    assert found
    for f in found:
        text = (text_of(f) + ' ' + f.remediation).lower()
        for phrase in FORBIDDEN_CLAIMS:
            assert phrase not in text, f'{f.extra["rule"]}: {phrase!r}'


def test_the_catalog_text_does_not_claim_rejection_prevents_exposure():
    for rule in ('COOKIE-SECURE-OVER-HTTP', 'COOKIE-SENSITIVE-OVER-HTTP', 'COOKIE-SAMESITE-NONE-INSECURE', 'COOKIE-PREFIX-INVALID'):
        r = get_rule(rule)
        text = f'{r.description} {r.impact_text} {r.remediation}'.lower()
        assert not any(p in text for p in FORBIDDEN_CLAIMS), rule
    impact = get_rule('COOKIE-SECURE-OVER-HTTP').impact_text
    assert 'crossed the network unencrypted' in impact and 'after the header has already been transmitted' in impact


def test_the_detector_documentation_keeps_transport_and_browser_handling_apart():
    import scanner.detectors.cookie_security as module
    doc = module.__doc__
    assert 'Transport:' in doc and 'Browser handling:' in doc
    assert 'rejecting a cookie does not un-send the header' in doc
    assert 'so it cannot be exposed' not in doc and 'it cannot leak' not in doc


def test_the_secure_over_http_finding_does_not_depend_on_the_cookie_name():
    assert rules(cookies('http://a.test/', f'theme=1; {HARD}')) == {'COOKIE-SECURE-OVER-HTTP'}
    assert cookies('http://a.test/', 'theme=1; HttpOnly; SameSite=Lax') == []           # ordinary and insecure: nothing to say


@pytest.mark.parametrize('url', ['http://localhost:8000/', 'http://127.0.0.1/', 'http://[::1]:8080/', 'http://app.localhost/'])
def test_trustworthy_origins_accept_secure_cookies_over_http_so_nothing_is_reported(url):
    assert cookies(url, f'sessionid=1; {HARD}') == []
    assert cookies(url, f'theme=1; {HARD}') == []
    assert cookies(url, 'sessionid=1; HttpOnly; SameSite=Lax') == []                  # existing behaviour: trustworthy, not flagged


def test_untrusted_lab_hostnames_are_judged_like_any_other_http_origin():
    assert rules(cookies('http://lab.test:8080/', f'sessionid=1; {HARD}')) == {'COOKIE-SECURE-OVER-HTTP'}
    assert rules(cookies('http://lab.test:8080/', 'sessionid=1; HttpOnly; SameSite=Lax')) == {'COOKIE-SENSITIVE-OVER-HTTP'}


def test_secure_cookies_over_https_get_neither_http_finding():
    assert cookies('https://a.test/', f'sessionid=1; {HARD}') == []


def test_both_http_situations_on_one_site_are_told_apart():
    found = cookies('http://a.test/', f'sessionid=1; {HARD}', 'authtoken=2; HttpOnly; SameSite=Lax')
    assert names(found, 'COOKIE-SECURE-OVER-HTTP') == ['sessionid'] and names(found, 'COOKIE-SENSITIVE-OVER-HTTP') == ['authtoken']


@pytest.mark.parametrize('header', ['__Secure-sessionid=1; Secure; HttpOnly; SameSite=Lax', '__Host-sessionid=1; Secure; HttpOnly; SameSite=Lax; Path=/'])
def test_exact_prefix_cookies_over_untrusted_http_report_the_prefix_finding_with_the_header_exposure(header):
    found = cookies('http://a.test/', header)
    assert rules(found) == {'COOKIE-PREFIX-INVALID'}                                   # one finding, no duplicate for the same cause
    f = only(found, 'COOKIE-PREFIX-INVALID')
    assert 'plain HTTP' in f.evidence and f.confidence == 'Confirmed'
    assert 'Set-Cookie response header, including the cookie value, was transmitted over plain HTTP' in f.evidence


@pytest.mark.parametrize('header', ['__Host-sessionid=1; HttpOnly; SameSite=Lax; Path=/', '__Secure-sessionid=1; HttpOnly; SameSite=Lax'])
def test_exact_prefix_cookies_without_secure_over_http_also_get_the_cleartext_finding(header):
    found = cookies('http://a.test/', header)
    assert rules(found) == {'COOKIE-PREFIX-INVALID', 'COOKIE-SENSITIVE-OVER-HTTP'}
    assert 'an invalid prefix' in only(found, 'COOKIE-SENSITIVE-OVER-HTTP').evidence


@pytest.mark.parametrize('name', ['__secure-sessionid', '__SECURE-sessionid', '__sEcure-sessionid', '__host-sessionid', '__HOST-sessionid'])
def test_case_variant_prefix_over_untrusted_http_does_not_hide_the_transport_exposure(name):
    """Regression: any recognised prefix spelling used to suppress COOKIE-SECURE-OVER-HTTP."""
    path = '; Path=/' if name.lower().startswith('__host') else ''
    found = cookies('http://a.test/', f'{name}=1; Secure; HttpOnly; SameSite=Lax{path}')
    assert rules(found) == {'COOKIE-PREFIX-INVALID', 'COOKIE-SECURE-OVER-HTTP'}
    assert only(found, 'COOKIE-PREFIX-INVALID').confidence == 'Potential'              # enforcement is browser-dependent
    f = only(found, 'COOKIE-SECURE-OVER-HTTP')
    assert f.confidence == 'Confirmed' and 'was transmitted over plain HTTP' in f.evidence


def test_case_variant_prefix_over_https_with_secure_is_not_an_http_finding():
    assert rules(cookies('https://a.test/', '__secure-sessionid=1; Secure; HttpOnly; SameSite=Lax')) == set()


def test_case_variant_prefix_without_secure_over_http_reports_the_cleartext_finding_too():
    found = cookies('http://a.test/', '__secure-sessionid=1; HttpOnly; SameSite=Lax')
    assert rules(found) == {'COOKIE-PREFIX-INVALID', 'COOKIE-SENSITIVE-OVER-HTTP'}
    assert 'browsers accept it' in only(found, 'COOKIE-SENSITIVE-OVER-HTTP').evidence     # variant: acceptance is not ruled out


@pytest.mark.parametrize('url', ['http://localhost:8000/', 'http://127.0.0.1/'])
def test_trustworthy_origins_get_no_transport_finding_for_prefix_variants(url):
    assert 'COOKIE-SECURE-OVER-HTTP' not in rules(cookies(url, '__secure-sessionid=1; Secure; HttpOnly; SameSite=Lax'))


def test_secure_over_http_is_aggregated_per_cookie_across_pages():
    found = detect(resp('http://a.test/a', [f'sid=1; {HARD}']), resp('http://a.test/b', [f'sid=1; {HARD}']))
    (f,) = found
    assert f.extra['rule'] == 'COOKIE-SECURE-OVER-HTTP' and len(f.affected_urls) == 2


def test_cookie_values_never_appear_in_the_new_findings():
    found = cookies('http://a.test/', f'sessionid=SECRETVALUE0123; {HARD}') + cookies('https://a.test/', 'sid=SECRETVALUE0123; HttpOnly; SameSite=None')
    assert found and all('SECRETVALUE0123' not in text_of(f) + json.dumps(f.to_dict()) + repr(f) for f in found)


# ---------------------------------------------------------------- __Host- case variants and Domain scope
def test_canonical_host_prefix_with_domain_is_only_a_prefix_finding():
    found = cookies('https://a.test/', f'__Host-sessionid=1; {HARD}; Path=/; Domain=a.test')
    f = only(found, 'COOKIE-PREFIX-INVALID')
    assert rules(found) == {'COOKIE-PREFIX-INVALID'} and f.confidence == 'Confirmed' and 'sets a Domain attribute' in f.evidence


@pytest.mark.parametrize('prefix', ['__host-', '__HOST-', '__hOsT-'])
def test_case_variant_host_prefix_with_domain_is_also_analyzed_for_scope(prefix):
    """Regression: the scope check used to skip every spelling of __host-, though enforcement of variants is browser dependent."""
    found = cookies('https://a.test/', f'{prefix}sessionid=1; {HARD}; Path=/; Domain=a.test')
    assert rules(found) == {'COOKIE-PREFIX-INVALID', 'COOKIE-BROAD-DOMAIN'}
    assert only(found, 'COOKIE-PREFIX-INVALID').confidence == 'Potential' and only(found, 'COOKIE-BROAD-DOMAIN').confidence == 'Potential'
    assert 'every subdomain of a.test' in only(found, 'COOKIE-BROAD-DOMAIN').evidence


@pytest.mark.parametrize('prefix', ['__Secure-', '__secure-', '__SECURE-'])
def test_secure_prefix_allows_domain_so_scope_is_analyzed_in_every_spelling(prefix):
    found = cookies('https://a.test/', f'{prefix}sessionid=1; {HARD}; Path=/; Domain=a.test')
    assert rules(found) == {'COOKIE-BROAD-DOMAIN'}


@pytest.mark.parametrize('prefix', ['__Host-', '__host-', '__HOST-'])
def test_host_prefix_without_domain_never_gets_a_scope_finding(prefix):
    assert 'COOKIE-BROAD-DOMAIN' not in rules(cookies('https://a.test/', f'{prefix}sessionid=1; {HARD}; Path=/'))


@pytest.mark.parametrize('prefix', ['__Host-', '__host-'])
def test_ordinary_names_with_host_prefix_and_domain_get_no_scope_finding(prefix):
    assert 'COOKIE-BROAD-DOMAIN' not in rules(cookies('https://a.test/', f'{prefix}theme=1; {HARD}; Path=/; Domain=a.test'))


# ================================================================ passive by construction
class ExplodingClient:
    def __getattr__(self, name):
        raise AssertionError(f'the cookie detector touched the client ({name})')


def test_detector_never_touches_the_http_client():
    found = detect(resp('https://a.test/', ['sessionid=1']), client=ExplodingClient())
    assert found


def test_detector_source_has_no_network_or_client_access():
    text = (ROOT / 'scanner' / 'detectors' / 'cookie_security.py').read_text(encoding='utf-8')
    code = re.sub(r'""".*?"""', '', text, flags=re.S)
    for forbidden in (r'\.client\b', r'urllib\.request', r'\bsocket\b', r'http\.client', r'(import|from) requests\b', r'(import|from) httpx\b',
                      r'\bprint\(', r'\blogging\b', r'\baffected_urls\b', r'\.body\b', r'\.text\(\)'):
        assert not re.search(forbidden, code), f'cookie_security.py must not use {forbidden}'


def test_documentation_describes_digest_collisions_as_negligible_not_impossible():
    import scanner.detectors.cookie_security as module
    text = Path(module.__file__).read_text(encoding='utf-8')
    assert 'negligible' in text and 'below 10^-30' in text
    assert not re.search(r'\b(impossible|cannot collide|can never collide|never collide)\b', text, re.I)
    assert not re.search(r'distinct long names never merge', text)


# ================================================================ registry and catalog
def test_detector_is_registered_in_its_category_only():
    detectors = get_detectors({'cookie_security'})
    assert [type(d).__name__ for d in detectors] == ['CookieSecurityDetector']
    assert 'cookie_security' in CATEGORIES and all(d.category != 'cookie_security' for d in get_detectors({'security_headers'}))


def test_every_rule_the_detector_can_emit_exists_in_the_catalog():
    source = (ROOT / 'scanner' / 'detectors' / 'cookie_security.py').read_text(encoding='utf-8')
    used = set(re.findall(r"'(COOKIE-[A-Z-]+)'", source))
    assert used and used <= set(RULES)
    assert {r for r in RULES if r.startswith('COOKIE-')} == used          # no unused cookie rule is left in the catalog


def test_cookie_rules_are_complete_and_categorized():
    for rule in (r for r in RULES.values() if r.id.startswith('COOKIE-')):
        assert rule.category == 'cookie_security' and rule.reference.startswith('OWASP WSTG')
        assert rule.description and rule.impact_text and rule.remediation and rule.method.startswith('Passive')


# ================================================================ end to end through the real engine
@pytest.fixture
def engine(lab_config, resolver, clock):
    def factory(target, config, resolver):
        return ScanHTTPClient(target, config, resolver=resolver, clock=clock.now, sleep=clock.sleep)
    return ScanEngine(config=lab_config, resolver=resolver, client_factory=factory)


CK = {'cookie_security'}
HTML = ('Content-Type', 'text/html')


def test_engine_scan_reports_cookie_gaps_from_real_crawled_responses(make_server, engine):
    srv = make_server({
        '/': (200, [HTML, ('Set-Cookie', 'sessionid=SECRETVALUE0123; Path=/'), ('Set-Cookie', 'theme=dark; HttpOnly; SameSite=Lax')],
              b'<a href="/a">a</a>'),
        '/a': (200, [HTML, ('Set-Cookie', 'sessionid=SECRETVALUE0123; Path=/; HttpOnly')], b'<p>a</p>')})
    out = engine.run(srv.base + '/', True, CK)
    assert out.status == 'completed' and out.pages_crawled == 2
    by_rule = {f.extra['rule']: f for f in out.findings}
    assert set(by_rule) == {'COOKIE-SENSITIVE-OVER-HTTP', 'COOKIE-NO-HTTPONLY', 'COOKIE-SAMESITE-MISSING'}
    assert len(by_rule['COOKIE-SENSITIVE-OVER-HTTP'].affected_urls) == 2 and len(by_rule['COOKIE-NO-HTTPONLY'].affected_urls) == 1
    assert out.requests_used == len(srv.seen) == 2                           # the detector added no requests
    assert all(f.category == 'cookie_security' for f in out.findings)


def test_engine_scan_tells_a_rejected_secure_cookie_from_an_exposed_insecure_one(make_server, engine):
    srv = make_server({'/': (200, [HTML, ('Set-Cookie', 'sessionid=SECRETVALUE0123; Secure; HttpOnly; SameSite=Lax'),
                                   ('Set-Cookie', 'authtoken=SECRETVALUE0123; HttpOnly; SameSite=Lax')], b'<p>x</p>')})
    out = engine.run(srv.base + '/', True, CK)                                # lab.test over plain HTTP: not a trustworthy origin
    by_rule = {f.extra['rule']: f for f in out.findings}
    assert set(by_rule) == {'COOKIE-SECURE-OVER-HTTP', 'COOKIE-SENSITIVE-OVER-HTTP'}
    assert by_rule['COOKIE-SECURE-OVER-HTTP'].extra['cookie_name'] == 'sessionid'
    assert by_rule['COOKIE-SENSITIVE-OVER-HTTP'].extra['cookie_name'] == 'authtoken'
    assert out.requests_used == len(srv.seen) == 1 and 'SECRETVALUE0123' not in repr(out) + json.dumps([f.to_dict() for f in out.findings])


def test_engine_scan_of_a_well_configured_server_reports_nothing(make_server, engine):
    srv = make_server({'/': (200, [HTML, ('Set-Cookie', 'theme=dark; HttpOnly; SameSite=Lax')], b'x')})
    out = engine.run(srv.base + '/', True, CK)
    assert out.status == 'completed' and out.findings == [] and out.errors == []


def test_engine_scan_over_https_checks_the_secure_attribute(make_server, engine, make_cert):
    srv = make_server({'/': (200, [HTML, ('Set-Cookie', 'sessionid=SECRETVALUE0123; HttpOnly; SameSite=Lax')], b'<p>s</p>')},
                      tls=make_cert('lab.test', 'lab.test'))
    out = engine.run(srv.base + '/', True, CK)
    assert {f.extra['rule'] for f in out.findings} == {'COOKIE-NO-SECURE'} and out.findings[0].severity == 'Medium'
    srv.routes['/'] = (200, [HTML, ('Set-Cookie', 'sessionid=SECRETVALUE0123; Secure; HttpOnly; SameSite=Lax')], b'<p>s</p>')
    assert engine.run(srv.base + '/', True, CK).findings == []


def test_engine_output_never_contains_cookie_values(make_server, engine, caplog, capsys):
    page = [HTML, ('Set-Cookie', 'sessionid=SECRETVALUE0123'), ('Set-Cookie', 'jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij; Domain=lab.test'),
            ('Set-Cookie', 'theme=SECRETVALUE0123; SameSite=None')]
    srv = make_server({'/': (200, page, b'<a href="/p?sig=QUERYSEC">p</a>'), '/p': (200, page, b'x')})
    with caplog.at_level(logging.DEBUG):
        out = engine.run(srv.base + '/', True, CK)
        print(out, out.findings)
    assert out.findings
    blob = ' '.join([repr(out), str(out.findings), json.dumps([f.to_dict() for f in out.findings]), caplog.text,
                     capsys.readouterr().out, ' '.join(out.errors + out.notes)])
    assert_no_value(blob, 'engine output')
    assert 'QUERYSEC' not in blob
    assert not [r for r in caplog.records if r.name.startswith('scanner')]


def test_engine_runs_cookie_and_header_detectors_together_without_interference(make_server, engine):
    srv = make_server({'/': (200, [HTML, ('Set-Cookie', 'theme=dark')], b'<p>x</p>')})
    both = engine.run(srv.base + '/', True, {'security_headers', 'cookie_security'})
    headers_only = engine.run(srv.base + '/', True, {'security_headers'})
    cookies_only = engine.run(srv.base + '/', True, CK)
    assert {f.category for f in both.findings} == {'security_headers', 'cookie_security'}
    assert {f.fingerprint() for f in both.findings} == {f.fingerprint() for f in headers_only.findings + cookies_only.findings}
    assert headers_only.findings and cookies_only.findings
    assert not any(f.category == 'cookie_security' for f in headers_only.findings)
    assert not any(f.category == 'security_headers' for f in cookies_only.findings)
    assert both.requests_used == 1                                           # still one page, no extra requests


# ================================================================ error handling: data is handled, bugs are not hidden
HOSTILE_HEADERS = ['', ' ', '=', '=x', ';', ';;;', 'a', 'a b=1', 'a=1;;;;', '\ud800=x', 'a=\ud800', 'a=1\x00', 'a=1\r\nX: y', 'é=1',
                   ' =1', 'a=1; Max-Age=' + '9' * 5000, 'a=1; Expires=not a date', 'a=1; Path', 'a=1; Domain=', 'a=1; SameSite',
                   'a' * 100_000 + '=1', 'a=1' + '; x' * 20_000, '__Host-=1', '__Secure-', '=' * 1000, 'sessionid', '\x7f=1', '"=1']


@pytest.mark.parametrize('header', HOSTILE_HEADERS)
def test_malformed_input_is_data_not_an_exception(header):
    """parse_set_cookie is total and run() has no try/except: unusable input yields None or a flagged cookie."""
    parse_set_cookie(header)                                  # must not raise
    cookies('http://a.test/', header)                         # the whole detector must not raise either


@pytest.mark.parametrize('header', HOSTILE_HEADERS)
def test_a_malformed_cookie_does_not_hide_the_cookies_around_it(header):
    found = cookies('http://a.test/', 'authtoken=1; HttpOnly; SameSite=Lax', header, 'sessionid=1; HttpOnly; SameSite=Lax')
    assert {f.extra['cookie_name'] for f in found if f.extra['rule'] == 'COOKIE-SENSITIVE-OVER-HTTP'} >= {'authtoken', 'sessionid'}


def test_hostile_headers_on_many_responses_are_all_handled():
    found = detect(*[resp(f'http://a.test/{i}', HOSTILE_HEADERS + ['sessionid=1; HttpOnly; SameSite=Lax']) for i in range(3)])
    assert any(f.extra['rule'] == 'COOKIE-SENSITIVE-OVER-HTTP' and len(f.affected_urls) == 3 for f in found)


def test_seeded_random_headers_never_raise():
    import random
    rnd = random.Random(20261113)
    pieces = list('abcXYZ019=;, \t\r\n\x00\x7f"\\/:@%-_.é  İK') + [
        'Secure', 'HttpOnly', 'SameSite=', 'None', 'Lax', 'Strict', 'Max-Age=', 'Expires=', 'Domain=', 'Path=', '__Host-', '__Secure-',
        '__host-', 'sessionid', '9' * 30, 'Path=/', 'Domain=a.test', 'Domain=.a.test', 'Domain=com', 'csrftoken', 'xsrf-token']
    for url in ('https://a.test/', 'http://a.test/', 'http://localhost/', 'http://[::1]:8080/'):
        for _ in range(500):
            headers = [''.join(rnd.choice(pieces) for _ in range(rnd.randint(0, 10))) for _ in range(rnd.randint(1, 4))]
            cookies(url, *headers)


def test_run_has_no_blanket_exception_handler():
    import ast
    import inspect
    import textwrap
    from scanner.detectors.cookie_security import CookieSecurityDetector
    tree = ast.parse(textwrap.dedent(inspect.getsource(CookieSecurityDetector.run)))
    assert not [n for n in ast.walk(tree) if isinstance(n, (ast.Try, ast.ExceptHandler))]


def test_an_internal_error_in_check_is_not_swallowed(monkeypatch):
    def broken(self, found, r, c):
        raise RuntimeError('programming error in _check')
    monkeypatch.setattr(CookieSecurityDetector, '_check', broken)
    with pytest.raises(RuntimeError, match='programming error in _check'):
        cookies('http://a.test/', 'sessionid=1')


def test_an_internal_error_for_one_cookie_is_not_hidden_even_when_other_cookies_are_fine(monkeypatch):
    real = CookieSecurityDetector._check

    def flaky(self, found, r, c):
        if c.name == 'boom':
            raise KeyError('internal bug')
        return real(self, found, r, c)
    monkeypatch.setattr(CookieSecurityDetector, '_check', flaky)
    with pytest.raises(KeyError):
        cookies('http://a.test/', 'sessionid=1', 'boom=1', 'authtoken=1')


def test_an_error_in_the_parser_is_not_swallowed(monkeypatch):
    import scanner.detectors.cookie_security as module

    def broken(header, now=None):
        raise ValueError('parser bug')
    monkeypatch.setattr(module, 'parse_set_cookie', broken)
    with pytest.raises(ValueError, match='parser bug'):
        cookies('http://a.test/', 'sessionid=1')


def test_an_error_reading_the_headers_is_not_swallowed(monkeypatch):
    def broken(self, name):
        raise AttributeError('header access bug')
    monkeypatch.setattr(HttpResponse, 'header_all', broken)
    with pytest.raises(AttributeError, match='header access bug'):
        cookies('http://a.test/', 'sessionid=1')


def test_the_engine_reports_a_failing_cookie_detector_instead_of_a_clean_result(make_server, engine, monkeypatch):
    def broken(self, found, r, c):
        raise RuntimeError('SECRETVALUE0123 internal detail')
    monkeypatch.setattr(CookieSecurityDetector, '_check', broken)
    srv = make_server({'/': (200, [HTML, ('Set-Cookie', 'sessionid=SECRETVALUE0123')], b'<p>x</p>')})
    out = engine.run(srv.base + '/', True, CK)
    assert out.status == 'completed_with_errors' and out.findings == []
    assert out.errors == ['cookie-security: failed (RuntimeError).']                       # class only: no message, no value
    assert 'SECRETVALUE0123' not in repr(out) + ' '.join(out.errors)


def test_the_engine_stays_clean_for_hostile_but_handled_input(make_server, engine):
    srv = make_server({'/': (200, [HTML, ('Set-Cookie', 'a b=1'), ('Set-Cookie', '=x'), ('Set-Cookie', 'a=1; Max-Age=' + '9' * 500)], b'<p>x</p>')})
    out = engine.run(srv.base + '/', True, CK)
    assert out.status == 'completed' and out.errors == []
