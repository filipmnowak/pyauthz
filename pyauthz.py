import logging
import httpsig
import hashlib
import base64
import json
import re
import os
import email.utils as eutils
from calendar import timegm as tgm
from time import time
from copy import deepcopy
from json.decoder import JSONDecodeError
from httpsig.utils import CaseInsensitiveDict as cidict


class HTTPSigAuthZ:
    '''Verify (authorize) or sign request using httpsig module; based on:
        - Signing HTTP Messages (draft-cavage-http-signatures-03) standard draft
        - RFC 3230 - Instance Digests in HTTP
        - RFC 5843 - Additional Hash Algorithms for HTTP Instance Digests

        args:
            http_request : dict
                Signature of http_request: {'method': <method : str>, 'path': <path : str>,
                                            'headers': <headers : obj>, 'body': <body : obj>}
            id_and_key : tuple or str
                It must have this signature: (<key_id : str>, <key : str>)
                or
                be instance of str. In case of string, pyauthz will attempt to grab keys and
                their id from PYAUTHZ_API_KEYS environmental variable, and for signing or
                verification, key identified by str will be used.
                or
                be None. None is applicable in case of request verification and effects in
                dynamic key lookup in the PYAUTHZ_API_KEYS, becased on the key id mentioned
                in the authorization header.
            signature_ttl : int
                Time to live / time of validity of the request signature in seconds.
                Set by the client; causes 'signature_ttl' header to be added to the request.
                Default: 1, maximum accepted value: 86400 (one day / 24h).
            logger : logging.Logger, optional
                Logger object. Will be autoinitialized in case if not given by the caller.'''

    def __init__(self, http_request, id_and_key, signature_ttl=1, logger=None):
        if not isinstance(logger, logging.Logger):
            logging.basicConfig(level=logging.DEBUG)
            self.log = logging.getLogger(__name__)
        else:
            self.log = logger
        # normally we would not bother to check types or method signatures, but this is
        # for this use-case, we won't continue execution if preliminaries are not matched.
        if isinstance(http_request, dict):
            if ('headers' in http_request.keys() and
                'body' in http_request.keys() and
                'method' in http_request.keys() and
                'path' in http_request.keys() and
                len(http_request.keys()) == 4):
                self.http_request = deepcopy(http_request)
                self.http_request['headers'] = cidict(http_request['headers'])
        else:
            raise RuntimeError('invalid type / signature of ' +
                               '{0} parameter!'.format('http_request'))
        if isinstance(id_and_key, tuple):
            if (len(id_and_key) == 2 and
                all(isinstance(i, str) for i in id_and_key)):
                self.id_and_key = id_and_key
        if isinstance(id_and_key, str) or id_and_key is None:
            try:
                self.pyauthz_api_keys = json.loads(os.getenv('PYAUTHZ_API_KEYS'))
            except (TypeError, JSONDecodeError) as e:
                raise RuntimeError(e)
        if isinstance(id_and_key, str):
            try:
                self.id_and_key = id_and_key, self.pyauthz_api_keys[id_and_key]
            except KeyError as e:
                raise RuntimeError(e)
        if id_and_key is None:
            self.id_and_key = id_and_key
        # we will sign all of the headers which should be already available
        # from the application, to be returned / send.
        # if application is based on framework, most probably it will add additional
        # headers - they won't be signed
        if isinstance(signature_ttl, int):
            if signature_ttl >= 1 and signature_ttl <= 86400:
                self.signature_ttl = signature_ttl
        try:
            self.signature_ttl
        except KeyError as e:
            raise RuntimeError('invalid type / value of ' +
                               '{0} parameter!'.format('signature_ttl'))

    def gen_salt(self):
        return base64.b64encode(os.urandom(64)).decode()

    def check_ttl(self):
        if 'signature-ttl' in self.http_request['headers']:
            try:
                valid_until = (int(self.http_request['headers']['signature-ttl']) +
                               tgm(eutils.parsedate(self.http_request['headers']['date'])))
                now = int(time())
                if valid_until >= now:
                    return True
                else:
                    self.log.error('authorization failure! signature expired')
                    self.log.error('signature valid until: %s'
                                   % (eutils.formatdate(valid_until)))
                    self.log.error('time now: %s' % (eutils.formatdate(now)))
                    return False
            except Exception as e:
                self.log.error('authorization failed!', exc_info=e)
                return False
        else:
            self.log.error('authorization failed! no signature-ttl header in the request.')
            return False
        return False

    def sign_request(self):
        # adding extra headers
        self.http_request['headers']['signature-ttl'] = str(self.signature_ttl)
        self.http_request['headers']['pyautz-salt'] = self.gen_salt()
        digest_header_value = 'sha-256=' + self.body_digest()
        self.http_request['headers']['digest'] = digest_header_value
        self.request_target = ['(request-target)']
        self.request_target += [k for k in self.http_request['headers'].keys()]
        key_id, key = self.id_and_key
        hs = httpsig.HeaderSigner(key_id, key, algorithm="hmac-sha256",
                                  headers=self.request_target)
        return hs.sign(self.http_request['headers'],
                       method=self.http_request['method'],
                       path=self.http_request['path'])

    def body_digest(self):
        # in general RFC 3230 talks mainly about server-side, but will use it for a client.
        # we need hash for the request body if any we don't care about empty body, as
        # hashes from empty strings are fine or even used as test vectors
        # for hashing functions.
        h = hashlib.sha256()
        # before signing, in case of json payload, we need to bring it to canonical form.
        # in our case canonical form is json string sorted by keys and without any
        # whitespaces
        if len(self.http_request['body']) > 0:
            try:
                l = json.loads(self.http_request['body'])
            except (TypeError, JSONDecodeError) as e:
                l = None
            if not l:
                # looks like we can try hashing without canonicalization, as
                # body doesn't look like json string
                h.update(self.http_request['body'].encode())
            else:
                # get canonical form of json
                d = json.dumps(l, sort_keys=True, separators=(',', ':'))
                h.update(d.encode())
        else:
            h.update(self.http_request['body'].encode())

        digest = h.digest()
        digest = base64.b64encode(digest)
        # ascii safe
        return digest.decode()

    def verify_request(self):
        # digest is obligatory header in our setup no matter the HTTP method used by
        # the client
        try:
            self.http_request['headers']['digest']
        except KeyError as e:
            self.log.error('no digest header in processed request! authorization failure!')
            return False
        # extract hash from the header
        hash_from_headers = '='.join(self.http_request['headers']['digest'].split('=')[1:])
        if self.body_digest() != hash_from_headers:
            self.log.error('digest hash not the same as new hash! authorization failure!')
            return False
        if self.id_and_key is None:
            try:
                res = re.search('keyId="([a-zA-Z0-9/=]+)"',
                                self.http_request['headers']['authorization'])
            except TypeError as e:
                self.log.error('failed to extract keyId from authorization header! ' +
                               'authorization failure!', exc_info=e)
                return False
            try:
                keyid = res.group(1)
            except (IndexError, AttributeError) as e:
                self.log.error('failed to extract key from authorization header! ' +
                               'authorization failure!', exc_info=e)
                return False
            try:
                self.pyauthz_api_keys[keyid]
            except KeyError as e:
                    self.log.error('unknown key id! authorization failure!', exc_info=e)
                    return False
            self.id_and_key = keyid, self.pyauthz_api_keys[keyid]
        try:
            hv = httpsig.HeaderVerifier(self.http_request['headers'],
                                        self.id_and_key[1],
                                        method=self.http_request['method'],
                                        path=self.http_request['path'])
        # we don't really care what exactly is being thrown at us - in general
        # it means failed authorization
        except Exception as e:
            self.log.error('authorization failed: ', exc_info=e)
            return False
        try:
            return hv.verify() and self.check_ttl()
        except Exception as e:
            self.log.error('authorization failed: ', exc_info=e)
            return False


if __name__ == '__main__':
    print("no direct execution - import")
    exit(1)
