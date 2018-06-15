import base64
import http.client
import io
import json
import os
from typing import Callable, Mapping, Optional, Sequence, Tuple
import urllib.error
import urllib.request
import urllib.response
import uuid
import warnings

from fixture import FooService
from jose.constants import ALGORITHMS
from jose.jws import verify
from pytest import fixture

from nirum_jose.client import SigningHttpTransport


Response = Tuple[int, Mapping[str, str], bytes]
Handler = Callable[[str, str, Optional[bytes]], Response]


class FixtureOpener(urllib.request.OpenerDirector):

    def __init__(self, handler: Optional[Handler]=None) -> None:
        super().__init__()
        self._handler = handler
        self.records = []

    def handler(self, handler: Handler) -> Handler:
        if self._handler is not None:
            warnings.warn(
                f'The existing handler {self._handler!r} is replaced by '
                f'a new handler {handler!r}.'
            )
        self._handler = handler
        return handler

    def response_is(self, value, code: int=200) -> None:
        serialized = json.dumps(
            value,
            ensure_ascii=False,
            indent='  '
        ).encode('utf-8')

        @self.handler
        def handle(method: str, url: str, data: Optional[bytes]) -> Response:
            return code, {'Content-Type': 'application/json'}, serialized

    def _open(self, req, data=None):
        method = req.get_method()
        url = req.get_full_url()
        data = req.data
        self.records.append((method, url, data))
        if self.handler is None:
            code = 500
            headers = {'Content-Type': 'text/plain'}
            content = b'Any handler is configured.'
        else:
            code, headers, content = self._handler(method, url, data)
        assert isinstance(content, bytes)
        fp = io.BytesIO(content)
        hdrs = http.client.HTTPMessage()
        for name, value in headers.items():
            hdrs.add_header(name, value)
        if code >= 400:
            reason = http.client.responses[code]
            raise urllib.error.HTTPError(url, code, reason, hdrs, fp)
        return urllib.response.addinfourl(fp, hdrs, url, code)


@fixture
def fx_opener() -> FixtureOpener:
    return FixtureOpener()


@fixture
def fx_secret() -> str:
    return base64.b64encode(os.urandom(4096)).decode('ascii')


@fixture
def fx_transport(
    fx_opener: FixtureOpener,
    fx_secret: str,
) -> SigningHttpTransport:
    return SigningHttpTransport(
        url='http://localhost/',
        secret=fx_secret,
        algorithm='HS256',
        opener=fx_opener
    )


@fixture
def fx_client(fx_transport: SigningHttpTransport) -> FooService.Client:
    return FooService.Client(fx_transport)


def verify_json(payload: bytes,
                secret: str,
                algorithms: Sequence[str]=ALGORITHMS.SUPPORTED):
    return json.loads(verify(payload, secret, algorithms))


def test_arguments(fx_secret: str,
                   fx_opener: FixtureOpener,
                   fx_client: FooService.Client):
    fx_opener.response_is(None)
    rv = fx_client.no_return_no_error(
        a=uuid.UUID('f9644caf-0615-40a1-afd3-c7b13420fa0e'),
        b=1234
    )
    assert rv is None
    assert len(fx_opener.records) == 1
    assert fx_opener.records[-1][0] == 'POST'
    assert fx_opener.records[-1][1] == 'http://localhost/'
    assert verify_json(fx_opener.records[-1][2], fx_secret) == {
        '_method': 'no_return_no_error',
        'a': 'f9644caf-0615-40a1-afd3-c7b13420fa0e',
        'b': 1234,
    }
