"""
Detector plugin registry.

A detector is a class with `category`, `name` and `run(context) -> list[Finding]`, decorated
with @register. Modules placed in this package are imported automatically by discover(), so
a new check is added by dropping in a file: the engine never needs editing.

Detectors must be independent of each other, must use ONLY context.client for network access
(that is what enforces scope, budget and rate limits), and must stay non-destructive.
"""
import importlib
import pkgutil

CATEGORIES = {
    'security_headers': 'Security Headers',
    'cookie_security': 'Cookie Security',
    'ssl_tls': 'SSL/TLS',
    'information_disclosure': 'Information Disclosure',
    'security_configuration': 'Security Configuration',
}

_REGISTRY = {}


class BaseDetector:
    category = None
    name = None

    def run(self, context):
        raise NotImplementedError


def register(cls):
    if cls.category not in CATEGORIES:
        raise ValueError(f'Unknown detector category {cls.category!r}')
    if not cls.name:
        raise ValueError('Detectors need a name')
    _REGISTRY[cls.name] = cls
    return cls


def unregister(name):
    _REGISTRY.pop(name, None)


def discover():
    """Import every module in this package so their @register decorators run."""
    for mod in pkgutil.iter_modules(__path__):
        importlib.import_module(f'{__name__}.{mod.name}')


def get_detectors(categories=None):
    """Instances of registered detectors, optionally limited to `categories` (None = all)."""
    discover()
    if categories is not None:
        unknown = set(categories) - set(CATEGORIES)
        if unknown:
            raise ValueError(f'Unknown categories: {", ".join(sorted(unknown))}')
    return [cls() for _name, cls in sorted(_REGISTRY.items())
            if categories is None or cls.category in categories]
