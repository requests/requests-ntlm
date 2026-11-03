import base64
import io

import pytest
import requests
import spnego
from requests.adapters import BaseAdapter

from requests_ntlm import HttpNtlmAuth


class SeekableBody:
    """File-like upload without iteration, as accepted by Requests."""

    def __init__(self, stream):
        self.stream = stream

    def read(self, *args):
        return self.stream.read(*args)

    def seek(self, *args):
        return self.stream.seek(*args)

    def tell(self):
        return self.stream.tell()


class NtlmUploadAdapter(BaseAdapter):
    def __init__(self):
        self.context = spnego.server(
            protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm
        )
        self.bodies = []

    def send(self, request, **kwargs):
        self.bodies.append(request.body.read())
        response = requests.Response()
        response.request = request
        response.url = request.url
        response.connection = self
        response.raw = io.BytesIO()
        response.raw.release_conn = lambda: None
        response._content = b""
        auth = request.headers.get("Authorization")
        if auth:
            token = self.context.step(base64.b64decode(auth.split()[1]))
            if self.context.complete:
                response.status_code = 200
            else:
                response.status_code = 401
                response.headers["WWW-Authenticate"] = (
                    "NTLM " + base64.b64encode(token).decode()
                )
        else:
            response.status_code = 401
            response.headers["WWW-Authenticate"] = "NTLM"
        return response

    def close(self):
        pass


@pytest.mark.parametrize("text", [False, True, "filelike"])
@pytest.mark.parametrize("offset", [0, 3])
@pytest.mark.parametrize("method", ["POST", "PUT"])
def test_upload_rewound_for_both_ntlm_retries(
    tmp_path, monkeypatch, text, offset, method
):
    credentials = tmp_path / "users"
    credentials.write_text("DOMAIN:user:Password123!\n")
    monkeypatch.setenv("NTLM_USER_FILE", str(credentials))
    filename = tmp_path / "body"
    filename.write_bytes(b"prefix-body-content")
    with filename.open(
        "r" if text is True else "rb"
    ) as body, requests.Session() as session:
        if text == "filelike":
            body = SeekableBody(body)
        body.seek(offset)
        expected = body.read()
        body.seek(offset)
        adapter = NtlmUploadAdapter()
        session.mount("http://", adapter)
        result = session.request(
            method,
            "http://localhost/upload",
            data=body,
            auth=HttpNtlmAuth("DOMAIN\\user", "Password123!", send_cbt=False),
        )
        assert result.status_code == 200
        assert adapter.context.complete
        assert adapter.bodies == [expected, expected, expected]
        assert len(result.history) == 2


def test_unrewindable_body_fails_before_authentication():
    body = io.BytesIO(b"payload")
    request = requests.Request("PUT", "http://localhost/upload", data=body).prepare()
    request._body_position = object()
    body.read()
    response = requests.Response()
    response.request = request
    with pytest.raises(requests.exceptions.UnrewindableBodyError):
        HttpNtlmAuth(
            "DOMAIN\\user", "Password123!", send_cbt=False
        ).retry_using_http_NTLM_auth(
            "www-authenticate", "Authorization", response, "NTLM", {}
        )
    assert body.tell() == len(b"payload")


@pytest.mark.parametrize("position", [3, object()])
def test_auth_preserves_recorded_body_position(position):
    request = requests.Request(
        "PUT", "http://localhost/upload", data=io.BytesIO(b"payload")
    ).prepare()
    request._body_position = position
    HttpNtlmAuth("DOMAIN\\user", "Password123!")(request)
    assert request._body_position is position


def test_failed_custom_body_tell_is_not_rewound():
    class BrokenTell(SeekableBody):
        def tell(self):
            raise OSError("position unavailable")

    body = BrokenTell(io.BytesIO(b"payload"))
    request = requests.Request("PUT", "http://localhost/upload", data=body).prepare()
    auth = HttpNtlmAuth("DOMAIN\\user", "Password123!", send_cbt=False)
    auth(request)
    assert request._body_position is not None
    response = requests.Response()
    response.request = request
    with pytest.raises(requests.exceptions.UnrewindableBodyError):
        auth.retry_using_http_NTLM_auth(
            "www-authenticate", "Authorization", response, "NTLM", {}
        )
