import hashlib
import ssl
import re

from ntlm_auth import ntlm
from requests.auth import AuthBase
from socket import socket

class HttpNtlmAuth(AuthBase):
    """
    HTTP NTLM Authentication Handler for Requests.
    """

    def __init__(self, username, password, session=None):
        r"""Create an authentication handler for NTLM over HTTP.

        :param str username: Username in 'domain\\username' format
        :param str password: Password
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
        self.context = ntlm.Ntlm()

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
        # msg = "%s\\%s" % (self.domain, self.username) if self.domain else self.username

        # ntlm returns the headers as a base64 encoded bytestring. Convert to
        # a string.
        negotiate_message = self.context.create_negotiate_message(self.domain).decode('ascii')
        auth = '%s %s' % (auth_type, negotiate_message)
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

        # Parse the challenge in the ntlm context
        self.context.parse_challenge_message(ntlm_header_value[len(auth_strip):])

        # build response
        # Get the certificate of the server if using HTTPS
        server_certificate_hash = _get_server_cert(request.url)

        # Get the response based on the challenge message
        authenticate_message = self.context.create_authenticate_message(self.username, self.password, self.domain,
                                                                        server_certificate_hash=server_certificate_hash)
        authenticate_message = authenticate_message.decode('ascii')

        auth = '%s %s' % (auth_type, authenticate_message)
        request.headers[auth_header] = auth
        response3 = response2.connection.send(request, **args)

        # Update the history.
        response3.history.append(response)
        response3.history.append(response2)

        # Get the session_security object created by ntlm-auth for signing and sealing of messages
        self.session_security = self.context.session_security

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

def _get_server_cert(request_url):
    """
    Get the certificate at the request_url and return it as a SHA256 hash. Will check the endpoint if it
    is a https site and use the default port 443 is it isn't explicity specified in the URL. Used to send
    in with NTLMv2 authentication for Channel Binding Tokens

    :param request_url: The request url in the format https://endpoint:port/path
    :return: SHA256 hash of the DER encoded certificate at the request_url or None if not a HTTPS endpoint
    """
    host_pattern = re.compile('(?i)^https://?(?P<host>[0-9a-z-_.]+)(:(?P<port>\d+))?')
    match = host_pattern.match(request_url)

    if match:
        host = match.group('host')
        port = match.group('port')
        if not port:
            port = 443
        else:
            port = int(port)

        s = socket()
        c = ssl.wrap_socket(s)
        c.connect((host, port))
        server_certificate = c.getpeercert(True)
        hash_object = hashlib.sha256(server_certificate)
        return hash_object.hexdigest().upper()
    else:
        return None