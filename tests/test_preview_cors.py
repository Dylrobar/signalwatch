import unittest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient
from signalwatch.cors import SignalWatchCORS

class PreviewCorsTests(unittest.TestCase):
    def setUp(self):
        async def status(request):
            return JSONResponse({'error': 'authentication_required'}, status_code=401)
        app = Starlette(routes=[Route('/api/status', status)])
        self.client = TestClient(SignalWatchCORS(app, allow_origins=['https://*.lovable.app', 'https://*.lovableproject.com', 'https://custom.example'], allow_methods=['GET', 'POST', 'OPTIONS'], allow_headers=['Authorization', 'Content-Type']))

    def test_preflight_and_auth_headers(self):
        for origin in ['https://id-preview--123.lovable.app', 'https://a.b.lovableproject.com', 'https://custom.example']:
            response = self.client.options('/api/status', headers={'Origin': origin, 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization'})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['access-control-allow-origin'], origin)
            response = self.client.get('/api/status', headers={'Origin': origin})
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.headers['access-control-allow-origin'], origin)

    def test_reject_lookalikes_and_bad_preflight(self):
        for origin in ['https://lovable.app.evil.test', 'https://evil-lovable.app', 'http://x.lovable.app', 'null', 'https://lovable.app', 'https://x.lovable.app:9999']:
            response = self.client.get('/api/status', headers={'Origin': origin})
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.json()['error'], 'cors_origin_denied')
            self.assertNotIn('access-control-allow-origin', response.headers)
        response = self.client.options('/api/status', headers={'Origin': 'https://x.lovable.app', 'Access-Control-Request-Method': 'DELETE'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['error'], 'cors_denied')
        self.assertEqual(int(response.headers['content-length']), len(response.content))

    def test_non_browser_client(self):
        self.assertEqual(self.client.get('/api/status').status_code, 401)

    def test_config_patterns_and_render_port(self):
        import os
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from signalwatch.config import load_config
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'PORT': '10000', 'SIGNALWATCH_CORS_ORIGINS': 'https://*.lovable.app,https://*.lovableproject.com'}, clear=True):
            path = Path(directory) / 'config.json'
            path.write_text('{}')
            config = load_config(path)
            self.assertEqual(config['port'], 10000)
            self.assertEqual(len(config['cors_origins']), 2)
