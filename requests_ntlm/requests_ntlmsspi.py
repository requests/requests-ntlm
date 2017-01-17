from sspi import ClientAuth
from requests.auth import AuthBase

class HttpNtlmSspiAuth(AuthBase):
    """Requests extension to auto-authenticate user.

    HTTP NTLM Authentication using SSPI for passwordless login.
    """

    def __init__(self):
        self.AuthGen = ClientAuth("NTLM")

    def __call__(self, r):
        r.headers["Connection"] = "Keep-Alive"
        r.register_hook('response', self.response_hook)
        return r

    def response_hook(self, r, **kwargs):
        """
        Identifies the type of authentication needed and the header title
        and routes the information to perform the authentication dance
        """
        www_authenticate = r.headers.get('www-authenticate', '').lower()
        if r.status_code == 401 and 'ntlm' in www_authenticate:
            return self.apply_sspi('www-authenticate', 'Authorization', r, kwargs)

        proxy_authenticate = r.headers.get('proxy-authenticate', '').lower()
        if r.status_code == 407 and 'ntlm' in proxy_authenticate:
            return self.apply_sspi('proxy-authenticate', 'Proxy-authorization', r, kwargs)
        return r

    def authenticate(self, challenge=None):
        """Performs the authentication handshake

        Parameters
        ----------
        challenge : str, optional
            Challenge is the response encoded response from the web-server that is
            typically the response to the client's initial challenge. When `challenge`
            is called without a `challenge`, it generates the first challenge to the
            server that open the communication between them.

        Returns
        -------
        str
            Returns a challenge for the server. That will either initiate the
            communication, or respond to the webservice's challenge.
        """
        challenge = challenge.decode('base64') if challenge else None
        _, output_buffer = self.AuthGen.authorize(challenge)
        return 'NTLM %s' % output_buffer[0].Buffer.encode('base64').replace('\n', '')

    def new_request(self, response):
        response.content
        response.raw.release_conn()
        return response.request.copy()

    def apply_sspi(self, auth_header_field, auth_header, response, args):
        """Performs the authentication dance between server and client.
        """
        if auth_header in response.request.headers:
            return response

        # A streaming response breaks authentication. Disabled for authentication dance
        # set back to default (args) for final return
        request = self.new_request(response)
        request.headers[auth_header] = self.authenticate()
        response = response.connection.send(request, **dict(args, stream=False))

        # Previous request/response sent initial msg to begin dance.
        # Now we authenticate using the response
        request = self.new_request(response)
        ntlm_header_value = response.headers[auth_header_field][5:]
        request.headers[auth_header] = self.authenticate(ntlm_header_value)

        # In case authentication info stored in cookies
        request.headers['Cookie'] = response.headers.get('set-cookie')

        return response.connection.send(request, **args)
