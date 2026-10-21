#!/usr/bin/env python3
"""Read-only handshake diagnostics. Token comes only from the environment."""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='https://signalwatch-2ssi.onrender.com')
    parser.add_argument('--origin', required=True)
    args = parser.parse_args()
    base = args.base.rstrip('/')
    if base.endswith('/api'):
        parser.error('Use the base URL without /api')
    token = os.environ.get('SIGNALWATCH_API_TOKEN', '')
    checks = [('/health', 'GET', {}), ('/api/status', 'OPTIONS', {
        'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization'}),
        ('/api/status', 'GET', {'Authorization': 'Bearer ' + token} if token else {})]
    failed = False
    for path, method, extra in checks:
        req = urllib.request.Request(base + path, method=method, headers={'Origin': args.origin, **extra})
        try:
            try:
                response = urllib.request.urlopen(req, timeout=120)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                body = response.read(8 * 1024 * 1024)
                origins = response.headers.get_all('Access-Control-Allow-Origin', [])
                ok = response.status == 200 and origins == [args.origin]
                if method == 'GET' and response.status == 200:
                    try:
                        data = json.loads(body)
                        ok = ok and (data.get('service') == 'SignalWatch' if path == '/health' else isinstance(data.get('stats'), dict))
                    except (ValueError, AttributeError):
                        ok = False
                print(f'{method} {path}: HTTP {response.status}; CORS origins={origins}; {"PASS" if ok else "FAIL"}')
                failed |= not ok
        except (OSError, urllib.error.URLError) as error:
            print(f'{method} {path}: network/timeout failure ({type(error).__name__})')
            failed = True
    return int(failed)

if __name__ == '__main__':
    sys.exit(main())
