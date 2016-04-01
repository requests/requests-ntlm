from requests.auth import AuthBase
from ntlm3 import ntlm


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
        :param str session: Unused. Kept for backwards-compatibility.
        """
        if ntlm is None:
            raise Exception("NTLM libraries unavailable")

        # parse the username
        try:
            self.domain, self.username = username.split('\\', 1)
        except ValueError:
            try:
                self.username, self.domain = username.split('@', 1)
            except ValueError:
                self.username = username
                self.domain = '.'

        self.domain = self.domain.upper()

        self.password = password

    def retry_using_http_NTLM_auth(self, auth_header_field, auth_header,
                                   response, auth_type, args):
        """Attempt to authenticate using HTTP NTLM challenge/response."""
        if auth_header in response.request.headers:
            return response

        content_length = int(
            response.request.headers.get('Content-Length', '0'), base=10)
        if hasattr(response.request.body, 'seek'):
            if content_length > 0:
                response.request.body.seek(-content_length, 1)
            else:
                response.request.body.seek(0, 0)

        # Consume content and release the original connection
        # to allow our new request to reuse the same one.
        response.content
        response.raw.release_conn()
        request = response.request.copy()

        # initial auth header with username. will result in challenge
        msg = "%s\\%s" % (self.domain, self.username) if self.domain else self.username

        # ntlm returns the headers as a base64 encoded bytestring. Convert to
        # a string.
        auth = '%s %s' % (auth_type, ntlm.create_NTLM_NEGOTIATE_MESSAGE(msg).decode('ascii'))
        request.headers[auth_header] = auth

        # A streaming response breaks authentication.
        # This can be fixed by not streaming this request, which is safe
        # because the returned response3 will still have stream=True set if
        # specified in args. In addition, we expect this request to give us a
        # challenge and not the real content, so the content will be short
        # anyway.
        args_nostream = dict(args, stream=False)
        response2 = response.connection.send(request, **args_nostream)

        # needed to make NTLM auth compatible with requests-2.3.0

        # Consume content and release the original connection
        # to allow our new request to reuse the same one.
        response2.content
        response2.raw.release_conn()
        request = response2.request.copy()

        # this is important for some web applications that store
        # authentication-related info in cookies (it took a long time to
        # figure out)
        if response2.headers.get('set-cookie'):
            request.headers['Cookie'] = response2.headers.get('set-cookie')

        # get the challenge
        auth_header_value = response2.headers[auth_header_field]

        auth_strip = auth_type + ' '

        ntlm_header_value = next(
            s for s in (val.lstrip() for val in auth_header_value.split(','))
            if s.startswith(auth_strip)
        ).strip()

        ServerChallenge, NegotiateFlags = ntlm.parse_NTLM_CHALLENGE_MESSAGE(
            ntlm_header_value[len(auth_strip):]
        )

        # build response

        # ntlm returns the headers as a base64 encoded bytestring. Convert to a
        # string.
        auth = '%s %s' % (auth_type, ntlm.create_NTLM_AUTHENTICATE_MESSAGE(
            ServerChallenge, self.username, self.domain, self.password,
            NegotiateFlags
        ).decode('ascii'))
        request.headers[auth_header] = auth

        response3 = response2.connection.send(request, **args)

        # Update the history.
        response3.history.append(response)
        response3.history.append(response2)

        return response3

    def response_hook(self, r, **kwargs):
        """The actual hook handler."""
        www_authenticate = r.headers.get('www-authenticate', '').lower()
        if r.status_code == 401:
            # prefer NTLM over Negotiate if the server supports it...
            if 'ntlm' in www_authenticate:
                auth_type = 'NTLM'
            elif 'negotiate' in www_authenticate:
                auth_type = 'Negotiate'
            return self.retry_using_http_NTLM_auth('www-authenticate',
                                                   'Authorization', r, auth_type, kwargs)

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
