import json
import tempfile
import unittest
from pathlib import Path

from signalwatch.config import load_config
from signalwatch.sourcehub import source_catalog
from signalwatch.store import Store


class ZeroSetupIntegrationTests(unittest.TestCase):
    def test_new_public_sources_are_ready_without_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            config = load_config(Path(directory) / 'config.json')
            store = Store(config['db'])
            catalog = {row['id']: row for row in source_catalog(config, store)['items']}
            providers = {'ctlogs', 'gleif', 'corporate_discovery', 'importyeti_public', 'circl_misp', 'greynoise_public'}
            for provider in providers:
                with self.subTest(provider=provider):
                    self.assertTrue(config['provider_settings'][provider]['enabled'])
                    self.assertTrue(catalog[provider]['enabled'])
                    self.assertEqual(catalog[provider]['access'], 'public')
                    self.assertFalse(catalog[provider]['credential_configured'])
                    self.assertEqual(catalog[provider]['requirements'], [])
                    self.assertNotEqual(catalog[provider]['status'], 'unconfigured')
            self.assertFalse(catalog['certspotter']['enabled'])
            self.assertTrue(all(target.get('domain') and target.get('name') for target in config['source_targets']))
            self.assertEqual(store.stats()['observations'], 0)
            self.assertEqual(store.stats()['alerts'], 0)

    def test_saved_operator_choices_survive_new_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            settings = {'provider_settings': {'ctlogs': {'enabled': False}, 'crtsh': {'enabled': False}, 'gleif': {'enabled': False}, 'corporate_discovery': {'enabled': False}, 'circl_misp': {'enabled': False}}, 'sources': {'exposure': False, 'threat': False}, 'source_intervals': {'corporate': 120}, 'source_targets': [{'name': 'Existing company', 'domain': 'example.org', 'company_id': 'company:existing'}]}
            path.write_text(json.dumps(settings))
            config = load_config(path)
            for provider in settings['provider_settings']:
                self.assertFalse(config['provider_settings'][provider]['enabled'])
            self.assertFalse(config['sources']['exposure'])
            self.assertFalse(config['sources']['threat'])
            self.assertEqual(config['source_intervals']['corporate'], 120)
            self.assertEqual(config['source_targets'], settings['source_targets'])
            self.assertTrue(config['provider_settings']['greynoise_public']['enabled'])
