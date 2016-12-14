import hashlib
import sys
import warnings

from ntlm_auth import ntlm
from requests.auth import AuthBase
from requests.packages.urllib3.response import HTTPResponse

class HttpNtlmAuth(AuthBase):
    """
    HTTP NTLM Authentication Handler for Requests.

    Supports pass-the-hash.
    """

    def __init__(self, username, password, session=None, domain=None):
        """Create an authentication handler for NTLM over HTTP.

        :param str username: Username. If in either 'domain\\\\username'
            format or 'username@domain' format, username and domain will be
            parsed out of it. Otherwise, domain is set to '.' and username
            is left intact. If the domain parameter is set no parsing is done
            regardless of the username format.
        :param str password: Password
        :param str session: Unused. Kept for backwards-compatibility.
        :param str domain: Domain. If None will be parsed out of username.
        """
        if ntlm is None:
            raise Exception("NTLM libraries unavailable")

        if domain is not None:
            self.username = username
            self.domain = domain
        else:
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

        # This exposes the encrypt/decrypt methods used to encrypt and decrypt messages
        # sent after ntlm authentication. These methods are utilised by libraries that
        # call requests_ntlm to encrypt and decrypt the messages sent after authentication
        self.session_security = None

    def retry_using_http_NTLM_auth(self, auth_header_field, auth_header,
                                   response, auth_type, args):
        # Get the certificate of the server if using HTTPS for CBT
        server_certificate_hash = _get_server_cert(response)

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

        # ntlm returns the headers as a base64 encoded bytestring. Convert to
        # a string.
        context = ntlm.Ntlm()
        negotiate_message = context.create_negotiate_message(self.domain).decode('ascii')
        auth = u'%s %s' % (auth_type, negotiate_message)
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
        context.parse_challenge_message(ntlm_header_value[len(auth_strip):])

        # build response
        # Get the response based on the challenge message
        authenticate_message = context.create_authenticate_message(
            self.username,
            self.password,
            self.domain,
            server_certificate_hash=server_certificate_hash
        )
        authenticate_message = authenticate_message.decode('ascii')
        auth = u'%s %s' % (auth_type, authenticate_message)
        request.headers[auth_header] = auth

        response3 = response2.connection.send(request, **args)

        # Update the history.
        response3.history.append(response)
        response3.history.append(response2)

        # Get the session_security object created by ntlm-auth for signing and sealing of messages
        self.session_security = context.session_security

        return response3

    def response_hook(self, r, **kwargs):
        """The actual hook handler."""
        if r.status_code == 401:
            # Handle server auth.
            www_authenticate = r.headers.get('www-authenticate', '').lower()
            auth_type = _auth_type_from_header(www_authenticate)

            if auth_type is not None:
                return self.retry_using_http_NTLM_auth(
                    'www-authenticate',
                    'Authorization',
                    r,
                    auth_type,
                    kwargs
                )
        elif r.status_code == 407:
            # If we didn't have server auth, do proxy auth.
            proxy_authenticate = r.headers.get(
                'proxy-authenticate', ''
            ).lower()
            auth_type = _auth_type_from_header(proxy_authenticate)
            if auth_type is not None:
                return self.retry_using_http_NTLM_auth(
                    'proxy-authenticate',
                    'Proxy-authorization',
                    r,
                    auth_type,
                    kwargs
                )

        return r

    def __call__(self, r):
        # we must keep the connection because NTLM authenticates the
        # connection, not single requests
        r.headers["Connection"] = "Keep-Alive"

        r.register_hook('response', self.response_hook)
        return r


def _auth_type_from_header(header):
    """
    Given a WWW-Authenticate or Proxy-Authenticate header, returns the
    authentication type to use. We prefer NTLM over Negotiate if the server
    suppports it.
    """
    if 'ntlm' in header:
        return 'NTLM'
    elif 'negotiate' in header:
        return 'Negotiate'

    return None

def _get_server_cert(response):
    """
    Get the certificate at the request_url and return it as a SHA256 hash. Will get the raw socket from the
    original response from the server. This socket is then checked if it is an SSL socket and then used to
    get the hash of the certificate. The certificate hash is then used with NTLMv2 authentication for
    Channel Binding Tokens support. If the raw object is not a urllib3 HTTPReponse (default with requests)
    then no certificate will be returned.

    :param response: The original 401 response from the server
    :return: SHA256 hash of the DER encoded certificate at the request_url or None if not a HTTPS endpoint
    """
    certificate_hash = None
    raw_response = response.raw

    if isinstance(raw_response, HTTPResponse):
        if sys.version_info > (3, 0):
            socket = raw_response._fp.fp.raw._sock
        else:
            socket = raw_response._fp.fp._sock

        try:
            server_certificate = socket.getpeercert(True)
        except AttributeError:
            pass
        else:
            hash_object = hashlib.sha256(server_certificate)
            certificate_hash = hash_object.hexdigest().upper()
    else:
        warnings.warn("Requests is running with a non urllib3 backend, cannot retrieve server certificate for CBT", NoCertificateRetrievedWarning)

    return certificate_hash

class NoCertificateRetrievedWarning(Warning):
    pass
