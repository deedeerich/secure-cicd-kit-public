"""Thin CLI over evidence_store.core. JSON result on stdout; exit code from the result status."""
import argparse
import json
import os
import sys

from . import __version__, core
from . import results as S
from .auth import AzCliTokenProvider, FileTokenProvider, default_token_provider
from .blob import DEFAULT_API_VERSION, DEFAULT_ENDPOINT_SUFFIX, StoreTarget
from .contract import load_contract
from .errors import EvidenceStoreError, redact

CONTRACT_ENV = 'EVIDENCE_STORE_CONTRACT'
API_URL_ENV = 'EVIDENCE_API_URL'
API_AUDIENCE_ENV = 'EVIDENCE_API_AUDIENCE'
API_TOKEN_FILE_ENV = 'EVIDENCE_API_TOKEN_FILE'

EXIT = {S.OK: 0, S.ERROR: 1, S.ALREADY_PRESENT: 3, S.CONFLICT: 4, S.REFUSED: 5, S.AUTH: 6,
        S.NETWORK: 7, S.VERIFY_FAILED: 8, S.CHAIN_BROKEN: 9}


def _common(p):
    p.add_argument('--account', default='', help='storage account name (default: contract)')
    p.add_argument('--endpoint-suffix', default='',
                   help='core.windows.net (default) or core.usgovcloudapi.net')
    p.add_argument('--endpoint-url', default='',
                   help='full endpoint override (https; http only to loopback test servers)')
    p.add_argument('--api-version', default=DEFAULT_API_VERSION)
    p.add_argument('--contract', default='', help='store contract JSON (env %s)' % CONTRACT_ENV)
    p.add_argument('--token-file', default='',
                   help='file holding a bearer token (env EVIDENCE_STORE_TOKEN_FILE); else az')
    p.add_argument('--timeout', type=float, default=60.0, help='seconds per HTTP request')
    # accepted only so that supplying them is refused loudly rather than ignored
    for f in ('--connection-string', '--sas-token', '--account-key'):
        p.add_argument(f, default=None, help=argparse.SUPPRESS)


def build_parser():
    ap = argparse.ArgumentParser(prog='python -m evidence_store',
                                 description='Governed evidence store client (put-once).')
    ap.add_argument('--version', action='version', version=__version__)
    sub = ap.add_subparsers(dest='op', required=True)

    p = sub.add_parser('push', help='file or directory -> container/prefix, put-once')
    _common(p)
    p.add_argument('source')
    p.add_argument('--container', required=True)
    p.add_argument('--prefix', default='')
    p.add_argument('--tool', required=True, help='writer tool: usr, adr, kit, lz, harness')
    p.add_argument('--layer', choices=['reported', 'evaluated', 'corroborated', 'approved'])
    p.add_argument('--case-id')
    p.add_argument('--package-id')
    p.add_argument('--run-id')
    p.add_argument('--meta', action='append', default=[], metavar='KEY=VALUE',
                   help='index field for the receipt, e.g. source_system=entra (repeatable)')
    p.add_argument('--meta-file', help='JSON object of index fields')
    p.add_argument('--content-type')
    p.add_argument('--no-manifest', action='store_true')
    p.add_argument('--manifest', action='store_true', help='write a manifest for a single file')
    p.add_argument('--block-threshold-mib', type=float, default=32)
    p.add_argument('--block-size-mib', type=float, default=8)
    # Owner decisions 2026-11-24: write through the tool's own API app by default (the templates
    # set EVIDENCE_API_URL); with no API URL this is the direct path (the documented fallback).
    # Over the API's limits the object is written directly anyway (the large-object path).
    p.add_argument('--api-url', default=None,
                   help='the evidence API app of this tool, https://<app> (env %s); empty = direct'
                   % API_URL_ENV)
    p.add_argument('--api-audience', default=None,
                   help='token audience api://<app> (env %s), for az account get-access-token'
                   % API_AUDIENCE_ENV)
    p.add_argument('--api-token-file', default=None,
                   help='file holding a bearer token for the API audience (env %s)'
                   % API_TOKEN_FILE_ENV)

    p = sub.add_parser('verify', help='rehash and compare with the receipt (and seal chain)')
    _common(p)
    p.add_argument('--container', required=True)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--name')
    g.add_argument('--prefix')
    p.add_argument('--check-seal', action='store_true')

    p = sub.add_parser('seal', help='seal a container (sealer identity only)')
    _common(p)
    p.add_argument('--container', required=True)
    p.add_argument('--tool', default='sealer')
    p.add_argument('--skip-if-empty', action='store_true')

    p = sub.add_parser('find', help='list by prefix, or Find Blobs by Tags')
    _common(p)
    p.add_argument('--container')
    p.add_argument('--prefix')
    p.add_argument('--where', help='tag expression, e.g. "\\"product\\" = \'kit\'"')

    p = sub.add_parser('pull', help='download and verify into a local directory')
    _common(p)
    p.add_argument('--container', required=True)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--name')
    g.add_argument('--prefix')
    p.add_argument('--dest', required=True)
    p.add_argument('--allow-unverified', action='store_true')
    return ap


def _push_via_api(a, api_url, contract, target, storage_tp, wm):
    from . import api_client
    tok_file = a.api_token_file if a.api_token_file is not None else         os.environ.get(API_TOKEN_FILE_ENV, '')
    aud = a.api_audience if a.api_audience is not None else os.environ.get(API_AUDIENCE_ENV, '')
    if tok_file:
        api_tp = FileTokenProvider(tok_file)
    elif aud:
        api_tp = AzCliTokenProvider(resource=aud, timeout=60)
    else:
        return _emit({'operation': 'push', 'status': S.REFUSED, 'transport': 'api',
                      'message': '%s is set but neither %s (api://<app>) nor %s is: the client '
                                 'cannot get a token for the API'
                                 % (API_URL_ENV, API_AUDIENCE_ENV, API_TOKEN_FILE_ENV)},
                     EXIT[S.REFUSED])
    r = api_client.push_via_api(
        api_client.ApiTarget(api_url, timeout=max(a.timeout, 1.0)), api_tp, contract,
        tool=a.tool, source=a.source, container=a.container, prefix=a.prefix, layer=a.layer,
        case_id=a.case_id, package_id=a.package_id, run_id=a.run_id, index_fields=_meta(a),
        content_type=a.content_type, write_manifest=wm, direct=(target, storage_tp),
        block_threshold=int(a.block_threshold_mib * 1024 * 1024),
        block_size=max(1, int(a.block_size_mib * 1024 * 1024)))
    return _emit(r.doc, api_client.exit_code(r))


def _emit(obj, code):
    sys.stdout.write(json.dumps(obj, indent=2, sort_keys=True) + '\n')
    return code


def _meta(a):
    out = {}
    if a.meta_file:
        with open(a.meta_file, 'r', encoding='utf-8') as fh:
            out.update(json.load(fh))
    for kv in a.meta:
        if '=' not in kv:
            raise ValueError('--meta expects KEY=VALUE, got %r' % kv)
        k, v = kv.split('=', 1)
        out[k.strip().replace('-', '_')] = v
    return out


def main(argv=None):
    a = build_parser().parse_args(argv)
    try:
        return _run(a)
    except EvidenceStoreError as e:
        status = {'REFUSED': S.REFUSED, 'AUTH': S.AUTH, 'NETWORK': S.NETWORK}.get(e.kind,
                                                                                 S.ERROR)
        return _emit({'operation': a.op, 'status': status, 'message': str(e)}, EXIT[status])
    except (OSError, ValueError) as e:
        return _emit({'operation': a.op, 'status': S.ERROR,
                      'message': redact('%s: %s' % (type(e).__name__, e))}, EXIT[S.ERROR])


def _run(a):
    for flag in ('connection_string', 'sas_token', 'account_key'):
        if getattr(a, flag, None) is not None:
            return _emit({'operation': a.op, 'status': S.REFUSED,
                          'message': '--%s is refused: this client uses Entra bearer tokens only '
                                     '(no Shared Key, SAS or connection strings, ever)'
                                     % flag.replace('_', '-')}, EXIT[S.REFUSED])
    cpath = a.contract or os.environ.get(CONTRACT_ENV, '')
    contract = load_contract(cpath) if cpath else None
    target = StoreTarget(account=a.account or (contract.account if contract else ''),
                         endpoint_suffix=(a.endpoint_suffix or
                                          (contract.endpoint_suffix if contract else '') or
                                          DEFAULT_ENDPOINT_SUFFIX),
                         endpoint_url=a.endpoint_url, api_version=a.api_version,
                         timeout=a.timeout)
    tp = default_token_provider(a.token_file or None)
    if a.op == 'push':
        wm = False if a.no_manifest else (True if a.manifest else None)
        api_url = a.api_url if a.api_url is not None else os.environ.get(API_URL_ENV, '')
        if api_url:
            return _push_via_api(a, api_url, contract, target, tp, wm)
        r = core.push(target, tp, contract, tool=a.tool, source=a.source, container=a.container,
                      prefix=a.prefix, layer=a.layer, case_id=a.case_id,
                      package_id=a.package_id, run_id=a.run_id, index_fields=_meta(a),
                      content_type=a.content_type, write_manifest=wm,
                      block_threshold=int(a.block_threshold_mib * 1024 * 1024),
                      block_size=max(1, int(a.block_size_mib * 1024 * 1024)))
    elif a.op == 'verify':
        r = core.verify(target, tp, container=a.container, name=a.name, prefix=a.prefix,
                        check_seal=a.check_seal)
    elif a.op == 'seal':
        r = core.seal(target, tp, contract, container=a.container, tool=a.tool,
                      skip_if_empty=a.skip_if_empty)
    elif a.op == 'find':
        r = core.find(target, tp, container=a.container, prefix=a.prefix, where=a.where)
    else:
        r = core.pull(target, tp, container=a.container, dest=a.dest, name=a.name,
                      prefix=a.prefix, allow_unverified=a.allow_unverified)
    return _emit(r.to_dict(), EXIT.get(r.status, 1))
