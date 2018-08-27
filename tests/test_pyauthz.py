import sys
import os
sys.path.append("..")
sys.path.append(".")
from copy import deepcopy
from pyauthz import HTTPSigAuthZ as z
import email.utils as eutils
from time import time
import unittest
import logging
from logging import Logger


class NullHandler(logging.Handler):

    def emit(self, record):
        pass


class TestPyAuthZ(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.req = {'headers': {"Date": eutils.formatdate(),
                    "Host": "example.com"}, 'body': '{"b": 1, "a": 2 }',
                    'path': '/some/endpoint', 'method': 'GET'}
        self.id_and_key = ('someid', 'somekey')
        self.mute_logger = logging.getLogger().addHandler(NullHandler())

    def test_no_digest_header(self):
        req = deepcopy(self.req)
        hs = z(req, self.id_and_key, signature_ttl=120, logger=self.mute_logger)
        req['headers'] = hs.sign_request()
        del(req['headers']['digest'])
        hv = z(req, self.id_and_key, logger=self.mute_logger)
        self.assertFalse(hv.verify_request())

    def test_bad_digest_header(self):
        req = deepcopy(self.req)
        hs = z(req, self.id_and_key, signature_ttl=120, logger=self.mute_logger)
        req['headers'] = hs.sign_request()
        req['headers']['digest'] = 'bad'
        hv = z(req, self.id_and_key, logger=self.mute_logger)
        self.assertFalse(hv.verify_request())

    def test_broken_body(self):
        req = deepcopy(self.req)
        hs = z(req, self.id_and_key, signature_ttl=120, logger=self.mute_logger)
        req['headers'] = hs.sign_request()
        req['body'] = 'forsurebodywasntanythinglikethis!'
        hv = z(req, self.id_and_key, logger=self.mute_logger)
        self.assertFalse(hv.verify_request())

    def test_1M_body(self):
        req = deepcopy(self.req)
        req['body'] = 1048576 * 'A'
        hs = z(req, self.id_and_key, signature_ttl=120, logger=self.mute_logger)
        req['headers'] = hs.sign_request()
        hv = z(req, self.id_and_key, logger=self.mute_logger)
        self.assertTrue(hv.verify_request())

    def test_invalid_ttl_zero(self):
        req = deepcopy(self.req)
        self.assertRaises(AttributeError, z, req, self.id_and_key, 0,
                          logger=self.mute_logger)

    def test_invalid_ttl_minus(self):
        req = deepcopy(self.req)
        self.assertRaises(AttributeError, z, req, self.id_and_key, -1,
                          logger=self.mute_logger)

    def test_invalid_ttl_48h(self):
        req = deepcopy(self.req)
        self.assertRaises(AttributeError, z, req, self.id_and_key, (86400 * 2),
                          logger=self.mute_logger)

    def test_signature_expired(self):
        req = deepcopy(self.req)
        req['headers']['Date'] = eutils.formatdate(int(time()) - 120)
        hs = z(req, self.id_and_key, logger=self.mute_logger)
        req['headers'] = hs.sign_request()
        hv = z(req, self.id_and_key, logger=self.mute_logger)
        self.assertFalse(hv.verify_request())

    def test_100M_body(self):
        req = deepcopy(self.req)
        req['body'] = 100 * (1048576 * 'A')
        hs = z(req, self.id_and_key, signature_ttl=120, logger=self.mute_logger)
        req['headers'] = hs.sign_request()
        hv = z(req, self.id_and_key, logger=self.mute_logger)
        self.assertTrue(hv.verify_request())

    def test_valid_request(self):
        req = deepcopy(self.req)
        hs = z(req, self.id_and_key, signature_ttl=120, logger=self.mute_logger)
        req['headers'] = hs.sign_request()
        hv = z(req, self.id_and_key, logger=self.mute_logger)
        self.assertTrue(hv.verify_request())

    def test_extra_headers(self):
        req = deepcopy(self.req)
        hs = z(req, self.id_and_key, signature_ttl=120, logger=self.mute_logger)
        req['headers'] = hs.sign_request()
        req['headers']['extra_header'] = 'some value'
        hv = z(req, self.id_and_key, logger=self.mute_logger)
        self.assertTrue(hv.verify_request())

    def test_missing_header(self):
        req = deepcopy(self.req)
        hs = z(req, self.id_and_key, signature_ttl=120, logger=self.mute_logger)
        req['headers'] = hs.sign_request()
        del(req['headers']['date'])
        hv = z(req, self.id_and_key, logger=self.mute_logger)
        self.assertFalse(hv.verify_request())

    def test_bad_signature_header(self):
        req = deepcopy(self.req)
        hs = z(req, self.id_and_key, signature_ttl=120, logger=self.mute_logger)
        req['headers'] = hs.sign_request()
        req['headers']['authorization'] = 'bad signature etc.'
        hv = z(req, self.id_and_key, logger=self.mute_logger)
        self.assertFalse(hv.verify_request())

    def test_no_authorize_header(self):
        req = deepcopy(self.req)
        hs = z(req, self.id_and_key, signature_ttl=120, logger=self.mute_logger)
        req['headers'] = hs.sign_request()
        del(req['headers']['authorization'])
        hv = z(req, self.id_and_key, logger=self.mute_logger)
        self.assertFalse(hv.verify_request())

    def test_bad_key_id_request(self):
        pyauthz_api_keys_orig = os.getenv('PYAUTHZ_API_KEYS')
        os.environ['PYAUTHZ_API_KEYS'] = '{"keyid1": "key1", "keyid2": "key2"}'
        req = deepcopy(self.req)
        self.assertRaises(RuntimeError, z, req, 'nosuchkeyidhahahaha',
                          signature_ttl=120, logger=self.mute_logger)
        if pyauthz_api_keys_orig:
            os.environ['PYAUTHZ_API_KEYS'] = pyauthz_api_keys_orig

    def test_none_key_id_request(self):
        pyauthz_api_keys_orig = os.getenv('PYAUTHZ_API_KEYS')
        os.environ['PYAUTHZ_API_KEYS'] = '{"someid": "somekey"}'
        req = deepcopy(self.req)
        hs = z(req, self.id_and_key, signature_ttl=120, logger=self.mute_logger)
        req['headers'] = hs.sign_request()
        hv = z(req, id_and_key=None, logger=self.mute_logger)
        self.assertTrue(hv.verify_request())
        if pyauthz_api_keys_orig:
            os.environ['PYAUTHZ_API_KEYS'] = pyauthz_api_keys_orig

if __name__ == "__main__":
    unittest.main()
