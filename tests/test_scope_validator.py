import pytest

from scanner.config import ScannerConfig
from scanner.scope_validator import (ScopeError, check_in_scope, classify_ip, parse_url,
                                     validate_scan_request, validate_target)
from conftest import FakeResolver


def cfg(allow, lab=()):
    return ScannerConfig(allowlist=frozenset(allow), lab_targets=frozenset(lab))


def code_of(fn, *a, **kw):
    with pytest.raises(ScopeError) as exc:
        fn(*a, **kw)
    return exc.value.code


# ---- URL parsing ----------------------------------------------------------
@pytest.mark.parametrize('url,code', [
    ('ftp://example.com/', 'scheme_not_allowed'),
    ('file:///etc/passwd', 'scheme_not_allowed'),
    ('javascript:alert(1)', 'scheme_not_allowed'),
    ('gopher://example.com', 'scheme_not_allowed'),
    ('example.com', 'scheme_not_allowed'),
    ('', 'invalid_url'), (None, 'invalid_url'), ('   ', 'invalid_url'), (123, 'invalid_url'),
    ('http://user:pw@example.com/', 'credentials_in_url'),
    ('http://example.com@evil.test/', 'credentials_in_url'),
    ('http://example.com\\@evil.test/', 'invalid_url'),
    ('http://exa mple.com/', 'invalid_url'),
    ('http://example.com/\r\nX: y', 'invalid_url'),
    ('http:///path', 'invalid_host'),
    ('http://example.com:99999/', 'invalid_url'),
    ('http://example.com:0/', 'invalid_url'),
    ('http://' + 'a' * 300 + '.com/', 'invalid_host'),
    ('http://exa_mple.com/', 'invalid_host'),
    ('http://example.com/' + 'a' * 2100, 'invalid_url'),
    # numeric host tricks that libc would resolve to loopback
    ('http://2130706433/', 'invalid_host'), ('http://127.1/', 'invalid_host'),
    ('http://0x7f.0.0.1/', 'invalid_host'), ('http://0177.0.0.1/', 'invalid_host'),
])
def test_parse_rejects(url, code):
    assert code_of(parse_url, url) == code


def test_parse_normalizes():
    scheme, host, port, target, url = parse_url('HTTP://Example.COM:80/a/b?x=1#frag')
    assert (scheme, host, port, target) == ('http', 'example.com', 80, '/a/b?x=1')
    assert url == 'http://example.com/a/b?x=1'
    assert parse_url('https://example.com')[4] == 'https://example.com/'
    assert parse_url('http://[::1]:8000/x')[4] == 'http://[::1]:8000/x'


# ---- address classification ----------------------------------------------
@pytest.mark.parametrize('ip,kind', [
    ('93.184.216.34', 'public'), ('8.8.8.8', 'public'), ('2606:4700:4700::1111', 'public'),
    ('127.0.0.1', 'private'), ('10.1.2.3', 'private'), ('172.16.5.5', 'private'),
    ('192.168.0.1', 'private'), ('::1', 'private'), ('fc00::1', 'private'),
    ('169.254.169.254', 'blocked'), ('169.254.1.1', 'blocked'), ('fe80::1', 'blocked'),
    ('0.0.0.0', 'blocked'), ('::', 'blocked'), ('224.0.0.1', 'blocked'), ('ff02::1', 'blocked'),
    ('240.0.0.1', 'blocked'), ('255.255.255.255', 'blocked'), ('100.64.0.1', 'blocked'),
    ('::ffff:169.254.169.254', 'blocked'), ('::ffff:127.0.0.1', 'private'),
    ('64:ff9b::a9fe:a9fe', 'blocked'), ('2002:7f00:1::', 'blocked'),
])
def test_classify_ip(ip, kind):
    assert classify_ip(ip) == kind


# ---- full target validation ----------------------------------------------
PUBLIC = FakeResolver({'ok.test': '93.184.216.34'})


def test_accepts_allowlisted_public_target():
    t = validate_target('https://ok.test/app?x=1#f', cfg({'ok.test'}), PUBLIC)
    assert (t.host, t.port, t.scheme, t.ips, t.is_lab) == ('ok.test', 443, 'https', ('93.184.216.34',), False)
    assert t.url == 'https://ok.test/app?x=1'


def test_empty_allowlist_rejects_everything():
    assert code_of(validate_target, 'https://ok.test/', cfg(set()), PUBLIC) == 'host_not_allowlisted'


def test_unlisted_host_rejected_without_dns_lookup():
    r = FakeResolver({'other.test': '93.184.216.34'})
    assert code_of(validate_target, 'https://other.test/', cfg({'ok.test'}), r) == 'host_not_allowlisted'
    assert r.calls == []          # unapproved hosts are never even resolved


def test_allowlist_is_exact_not_suffix():
    r = FakeResolver({'sub.ok.test': '93.184.216.34', 'ok.test.evil.test': '93.184.216.34'})
    for host in ('sub.ok.test', 'ok.test.evil.test'):
        assert code_of(validate_target, f'https://{host}/', cfg({'ok.test'}), r) == 'host_not_allowlisted'


def test_allowlist_port_entries():
    r = FakeResolver({'ok.test': '93.184.216.34'})
    c = cfg({'ok.test:8443'})
    validate_target('https://ok.test:8443/', c, r)
    assert code_of(validate_target, 'https://ok.test/', c, r) == 'host_not_allowlisted'


@pytest.mark.parametrize('ip', ['127.0.0.1', '10.0.0.5', '192.168.1.1', '172.16.0.1', '169.254.169.254',
                                '0.0.0.0', '224.0.0.1', '100.64.0.1', '240.0.0.1', '::1', 'fe80::1',
                                '::ffff:127.0.0.1', 'fc00::1', '64:ff9b::7f00:1'])
def test_ip_literals_rejected_by_default_even_if_allowlisted(ip):
    host = f'[{ip}]' if ':' in ip else ip
    assert code_of(validate_target, f'http://{host}/', cfg({ip}), FakeResolver({})) == 'blocked_address'


def test_localhost_name_rejected_by_default():
    r = FakeResolver({'localhost': ['127.0.0.1', '::1']})
    assert code_of(validate_target, 'http://localhost:5000/', cfg({'localhost'}), r) == 'blocked_address'


def test_hostname_resolving_to_internal_address_rejected():
    r = FakeResolver({'ok.test': '10.0.0.8'})
    assert code_of(validate_target, 'https://ok.test/', cfg({'ok.test'}), r) == 'blocked_address'


def test_mixed_public_and_private_records_rejected():
    r = FakeResolver({'ok.test': ['93.184.216.34', '10.0.0.8']})
    assert code_of(validate_target, 'https://ok.test/', cfg({'ok.test'}), r) == 'blocked_address'


def test_dns_failure():
    assert code_of(validate_target, 'https://nx.test/', cfg({'nx.test'}), FakeResolver({})) == 'dns_failure'


# ---- lab targets: separate opt-in, never global ---------------------------
def test_lab_target_allows_private_only_when_both_listed():
    r = FakeResolver({'lab.test': '10.0.0.8'})
    t = validate_target('http://lab.test/', cfg({'lab.test'}, {'lab.test'}), r)
    assert t.is_lab and t.ips == ('10.0.0.8',)
    # lab-listed but not allowlisted -> rejected
    assert code_of(validate_target, 'http://lab.test/', cfg(set(), {'lab.test'}), r) == 'host_not_allowlisted'
    # allowlisted but not lab-listed -> private address still rejected
    assert code_of(validate_target, 'http://lab.test/', cfg({'lab.test'}), r) == 'blocked_address'


def test_lab_opt_in_is_per_host():
    r = FakeResolver({'lab.test': '127.0.0.1', 'other.test': '127.0.0.1'})
    c = cfg({'lab.test', 'other.test'}, {'lab.test'})
    validate_target('http://lab.test/', c, r)
    assert code_of(validate_target, 'http://other.test/', c, r) == 'blocked_address'


@pytest.mark.parametrize('ip', ['169.254.169.254', '0.0.0.0', '224.0.0.1', 'fe80::1', '100.64.0.1'])
def test_lab_targets_can_never_reach_metadata_or_reserved_ranges(ip):
    r = FakeResolver({'lab.test': ip})
    assert code_of(validate_target, 'http://lab.test/', cfg({'lab.test'}, {'lab.test'}), r) == 'blocked_address'


# ---- authorization attestation -------------------------------------------
@pytest.mark.parametrize('flag', [False, None, 'true', 'yes', 1, 0, [], {}])
def test_authorization_must_be_boolean_true(flag):
    assert code_of(validate_scan_request, 'https://ok.test/', flag, cfg({'ok.test'}), PUBLIC) == 'authorization_required'


def test_authorization_checked_before_any_dns():
    r = FakeResolver({'ok.test': '93.184.216.34'})
    code_of(validate_scan_request, 'https://ok.test/', False, cfg({'ok.test'}), r)
    assert r.calls == []
    assert validate_scan_request('https://ok.test/', True, cfg({'ok.test'}), r).host == 'ok.test'


# ---- redirect / crawl scope ----------------------------------------------
@pytest.fixture
def origin():
    return validate_target('http://lab.test:8000/', cfg({'lab.test', 'evil.test'}, {'lab.test'}),
                           FakeResolver({'lab.test': '127.0.0.1'}))


def test_in_scope_same_host(origin):
    c = cfg({'lab.test'})
    assert check_in_scope('http://lab.test:8000/a#x', origin, c) == 'http://lab.test:8000/a'
    assert check_in_scope('https://lab.test/secure', origin, c) == 'https://lab.test/secure'   # upgrade
    assert check_in_scope('HTTP://LAB.TEST:8000/x', origin, c).startswith('http://lab.test:8000')


@pytest.mark.parametrize('url,code', [
    ('http://evil.test/', 'out_of_scope'),                  # allowlisted elsewhere, still not this scan's scope
    ('http://127.0.0.1:8000/', 'out_of_scope'),
    ('http://lab.test:9999/', 'out_of_scope'),              # different port
    ('http://sub.lab.test:8000/', 'out_of_scope'),
    ('http://lab.test.evil.test:8000/', 'out_of_scope'),
    ('http://lab.test@evil.test/', 'credentials_in_url'),
    ('ftp://lab.test/', 'scheme_not_allowed'),
])
def test_out_of_scope_urls(origin, url, code):
    assert code_of(check_in_scope, url, origin, cfg({'lab.test', 'evil.test'})) == code
