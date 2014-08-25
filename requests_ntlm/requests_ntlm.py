from requests.auth import AuthBase
from requests.adapters import HTTPAdapter
from requests.models import PreparedRequest
from ntlm import ntlm
import weakref


class HttpNtlmAuth(AuthBase):
    """
    HTTP NTLM Authentication Handler for Requests.

    Supports pass-the-hash.
    """

    def __init__(self, username, password, session=None):
        r"""Create an authentication handler for NTLM over HTTP.

        :param str username: Username in 'domain\\username' format
        :param str password: Password or hash in
            "ABCDABCDABCDABCD:ABCDABCDABCDABCD" format.
        :param str session: Optional requests.Session, through which
            connections are pooled.
        """
        if ntlm is None:
            raise Exception("NTLM libraries unavailable")

        # parse the username
        try:
            self.domain, self.username = username.split('\\', 1)
        except ValueError:
            raise ValueError(
                r"username should be in 'domain\\username' format."
            )

        self.domain = self.domain.upper()

        self.password = password

        self.adapter = HTTPAdapter()

        # Keep a weak reference to the Session, if one is in use.
        # This is to avoid a circular reference.
        self.session = weakref.ref(session) if session else None

    def retry_using_http_NTLM_auth(self, auth_header_field, auth_header,
                                   response, args):
        """Attempt to authenticate using HTTP NTLM challenge/response."""
        if auth_header in response.request.headers:
            return response

        request = copy_request(response.request)

        content_length = int(request.headers.get('Content-Length', '0'),
                             base=10)
        if hasattr(request.body, 'seek'):
            if content_length > 0:
                request.body.seek(-content_length, 1)
            else:
                request.body.seek(0, 0)

        adapter = self.adapter
        if self.session:
            session = self.session()
            if session:
                adapter = session.get_adapter(response.request.url)

        # initial auth header with username. will result in challenge
        msg = "%s\\%s" % (self.domain, self.username) if self.domain else self.username
        auth = 'NTLM %s' % ntlm.create_NTLM_NEGOTIATE_MESSAGE(msg)
        request.headers[auth_header] = auth

        # A streaming response breaks authentication.
        # This can be fixed by not streaming this request, which is safe
        # because the returned response3 will still have stream=True set if
        # specified in args. In addition, we expect this request to give us a
        # challenge and not the real content, so the content will be short
        # anyway.
        args_nostream = dict(args, stream=False)
        response2 = adapter.send(request, **args_nostream)

        # needed to make NTLM auth compatible with requests-2.3.0
        response2.content

        # this is important for some web applications that store
        # authentication-related info in cookies (it took a long time to
        # figure out)
        if response2.headers.get('set-cookie'):
            request.headers['Cookie'] = response2.headers.get('set-cookie')

        # get the challenge
        auth_header_value = response2.headers[auth_header_field]
        ntlm_header_value = list(filter(
            lambda s: s.startswith('NTLM '), auth_header_value.split(',')
        ))[0].strip()
        ServerChallenge, NegotiateFlags = ntlm.parse_NTLM_CHALLENGE_MESSAGE(
            ntlm_header_value[5:]
        )

        # build response
        request = copy_request(request)
        auth = 'NTLM %s' % ntlm.create_NTLM_AUTHENTICATE_MESSAGE(
            ServerChallenge, self.username, self.domain, self.password,
            NegotiateFlags
        )
        request.headers[auth_header] = auth

        response3 = adapter.send(request, **args)

        # Update the history.
        response3.history.append(response)
        response3.history.append(response2)

        return response3

    def response_hook(self, r, **kwargs):
        """The actual hook handler."""
        www_authenticate = r.headers.get('www-authenticate', '').lower()
        if r.status_code == 401 and 'ntlm' in www_authenticate:
            return self.retry_using_http_NTLM_auth('www-authenticate',
                                                   'Authorization', r, kwargs)

        proxy_authenticate = r.headers.get('proxy-authenticate', '').lower()
        if r.status_code == 407 and 'ntlm' in proxy_authenticate:
            return self.retry_using_http_NTLM_auth('proxy-authenticate',
                                                   'Proxy-authorization', r,
                                                   kwargs)

        return r

    def __call__(self, r):
        # we must keep the connection because NTLM authenticates the
        # connection, not single requests
        r.headers["Connection"] = "Keep-Alive"

        r.register_hook('response', self.response_hook)
        return r


def copy_request(request):
    """Copy a Requests PreparedRequest."""
    new_request = PreparedRequest()

    new_request.method = request.method
    new_request.url = request.url
    new_request.body = request.body
    new_request.hooks = request.hooks
    new_request.headers = request.headers.copy()

    return new_request
