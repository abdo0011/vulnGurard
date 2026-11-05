import pytest

from scanner import config as cfg


@pytest.mark.parametrize('entry', ['*.example.com', 'https://example.com', 'example.com/path', 'a b',
                                   'user@example.com', '10.0.0.0/8', 'example.com:99999', 'example.com:abc',
                                   '::1'])
def test_scope_entries_reject_patterns_and_garbage(entry):
    with pytest.raises(cfg.ConfigError):
        cfg.normalize_entry(entry)


def test_scope_entry_normalization():
    assert cfg.normalize_entry(' Example.COM ') == 'example.com'
    assert cfg.normalize_entry('example.com:8080') == 'example.com:8080'
    assert cfg.normalize_entry('[::1]:8000') == '[::1]:8000'
    assert cfg.normalize_entry('127.0.0.1') == '127.0.0.1'
    assert cfg.normalize_entry('   ') is None


def test_load_config_from_env():
    c = cfg.load_config({'VULNGUARD_SCAN_ALLOWLIST': 'a.test, B.test:8443,',
                         'VULNGUARD_LAB_TARGETS': 'a.test', 'VULNGUARD_API_TOKEN': 'x' * 20})
    assert c.allowlist == {'a.test', 'b.test:8443'}
    assert c.lab_targets == {'a.test'}
    assert c.api_token == 'x' * 20
    empty = cfg.load_config({})
    assert not empty.allowlist and not empty.lab_targets and empty.api_token is None


def test_safety_ceilings_are_the_approved_values():
    assert (cfg.MAX_DEPTH, cfg.MAX_PAGES, cfg.MAX_REQUESTS) == (2, 20, 100)
    assert cfg.MIN_REQUEST_INTERVAL >= 0.5 and 'VulnGuard' in cfg.USER_AGENT


@pytest.mark.parametrize('host', ['127.0.0.1', 'localhost', '::1', '[::1]'])
def test_loopback_binding_needs_no_token(host):
    cfg.check_network_binding(host, debug=True, token=None)


@pytest.mark.parametrize('token', [None, '', 'short'])
def test_network_binding_requires_token(token):
    with pytest.raises(cfg.ConfigError, match='API_TOKEN'):
        cfg.check_network_binding('0.0.0.0', False, token)


def test_network_binding_refuses_debug_even_with_token():
    with pytest.raises(cfg.ConfigError, match='debug'):
        cfg.check_network_binding('192.168.1.5', True, 't' * 32)
    cfg.check_network_binding('192.168.1.5', False, 't' * 32)


def test_api_token_verification():
    open_cfg = cfg.ScannerConfig(frozenset(), frozenset(), None)
    locked = cfg.ScannerConfig(frozenset(), frozenset(), 'secret-token-1234')
    assert cfg.verify_api_token(open_cfg, None)
    assert cfg.verify_api_token(locked, 'secret-token-1234')
    assert not cfg.verify_api_token(locked, None)
    assert not cfg.verify_api_token(locked, 'wrong')
