"""evidence_store: a governed evidence-store client for Azure Blob (stdlib only).

Core API (plain functions; identity per call; JSON-serialisable results):

    push(target, token_provider, contract, *, tool, source, container, prefix='', ...)
    verify(target, token_provider, *, container, name=None, prefix=None, check_seal=False)
    seal(target, token_provider, contract, *, container, tool='sealer', ...)
    find(target, token_provider, *, container=None, prefix=None, where=None)
    pull(target, token_provider, *, container, dest, name=None, prefix=None, ...)
"""
__version__ = '0.1.0'

from .auth import (AzCliTokenProvider, ChainTokenProvider, FileTokenProvider,  # noqa: E402
                   StaticTokenProvider, default_token_provider, writer_from_token)
from .blob import (DEFAULT_API_VERSION, DEFAULT_ENDPOINT_SUFFIX,  # noqa: E402
                   GOV_ENDPOINT_SUFFIX, StoreTarget)
from .contract import StoreContract, load_contract, parse_contract  # noqa: E402
from .core import find, pull, push, seal, verify, verify_seal_chain  # noqa: E402

__all__ = ['__version__', 'push', 'verify', 'seal', 'find', 'pull', 'verify_seal_chain',
           'StoreTarget', 'StoreContract', 'load_contract', 'parse_contract',
           'StaticTokenProvider', 'FileTokenProvider', 'AzCliTokenProvider',
           'ChainTokenProvider', 'default_token_provider', 'writer_from_token',
           'DEFAULT_API_VERSION', 'DEFAULT_ENDPOINT_SUFFIX', 'GOV_ENDPOINT_SUFFIX']
