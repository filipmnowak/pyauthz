[![Total alerts](https://img.shields.io/lgtm/alerts/g/filipmnowak/pyauthz.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/filipmnowak/pyauthz/alerts/) [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/filipmnowak/pyauthz.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/filipmnowak/pyauthz/context:python)

# pyauthz 

Verify (authorize) or sign request using [httpsig](https://github.com/ahknight/httpsig/) module; based on:

    * Signing HTTP Messages (draft-cavage-http-signatures-03) standard draft
    * RFC 3230 - Instance Digests in HTTP
    * RFC 5843 - Additional Hash Algorithms for HTTP Instance Digests

Purpose of the module is to enable backend to backend conversation authorized with
API keys but without exposing the key itself.

It acts as convenience layer and supplements [httpsig](https://github.com/ahknight/httpsig/) with:

    * signature TTL
    * request body digest to improve request integrity protection
    * some help with verification key choice
    * salt header to increase security of HMAC signature

This is experimantal software and it might not be fit for production usage! Use with caution, please report any issues.

## Dependencies:

Beside standard Python modules:

* [httpsig 1.2.0](https://pypi.python.org/pypi/httpsig/1.2.0)

## Usage

Basic example:

* in contenerized environments you may want to start with exporting json string
  containing API keys you want to use (alternatively, you can provide id and key during class
  instantialization):

```bash
export PYAUTHZ_API_KEYS='{"someid1": "somekey1", "someid2": "somekey2", "someid3": "somekey3"}'
```

* import module:

```python
>>> from pyauthz import HTTPSigAuthZ as z
```

* set required data (all of the headers from the requests fed to the method will be
  used from creation of the signature):

```python
>>> keyid_and_key = ('someid', 'somekey')
>>> req = {'headers': {"Date": "Fri Oct  5 21:39:45 CEST 2018", "Host": 
... "example.com"},'body': '{"z": 1, "a": 2 }', 'path': '/some/endpoint', 'method': 'GET'}
```

* to sign: create instance, and create signed headers dictionary:

```python
>>> hs = z(req, keyid_and_key, 120)
>>> signed_headers = hs.sign_request()
>>> signed_headers
{'date': 'Fri Oct  5 21:39:45 CEST 2018', 'host': 'example.com', 'signature-ttl': '120', 'pyauthz-salt': 
'SuUpmh78GxP/LctVk5HjsUfTp8LB4B6p+DIW8imSPXCPxSWsiW62nL+8DokvptG79t8VhJwxmRKSnetWPwpP7Q==', 
'digest': 'sha-256=wphcW6b30qVedo+SSQygk4jpW8TMy5/fEbFfTUL5PnM=', 'authorization': 'Signature 
keyId="someid",algorithm="hmac-sha256",signature="Y9q4PlLX9wXEndz8Ggn13aiqq23Klk89hF0wbiWLHQc=",
headers="(request-target) date host signature-ttl pyauthz-salt digest"'}
```

* to verify, similar steps (please note order of the keys in the body of the request
was changed - this will work also, because we are generating `digest` header using
canonical form of the json payload):

```python
>>> req = {'headers': signed_headers, 'body': '{"a": 2, "z": 1 }',
... 'path': '/some/endpoint', 'method': 'GET'}
>>> hv = z(req, keyid_and_key)
>>> hv.verify_request()
True
>>>
```

## Security

Scheme is susceptible to reply attack - potential attacker can "records" whole
HTTP request, (including authorization header) and reply it until it is valid.

This is due to compromise between security and functionality (issue can be solved
with server-provided nonce, but this requires round trips - which are the
case in [HTTP Digest](https://en.wikipedia.org/wiki/Digest_access_authentication) auth) -
this module offers stateless authorization.

To lower the risk, please use TLS and tune `signature_ttl` parameter during class
initialization. 

Especially in production environment, it is good idea to use TLS in addition to this module.

It is possible that HTTP client will add some extra headers, after signing procedure will take place, same
can be true if proxy servers come into play.
HTTP headers can also be added during main-in-the-middle attack (especially in case of non-TLS, plain HTTP connection).
Those headers can change behavior of the remote HTTP server or application (verifier).

## Contributing

You are more then welcome to fork it and contribute by creating pull requests.
In case of any other need, please let me know.

Please make sure your code is compliant with [PEP8 standard](https://www.python.org/dev/peps/pep-0008/), with some tweaks allowed:

* E402 - in tests, module-level imports not being placed at the top of the source file are fine.
* E501 - maximum line length is set to 92 characters (more practical and still tidy / readable)
* E265 - it is OK to comment code without adding space after `#`

## License

[GPLv3](https://www.gnu.org/licenses/gpl-3.0.txt); see [LICENSE.txt](LICENSE.txt)  
Copyright © 2018 Filip M. Nowak
