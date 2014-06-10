from requests.auth import AuthBase
from requests.adapters import HTTPAdapter
from requests.models import PreparedRequest
from ntlm import ntlm
import base64


class WinAuth(AuthBase):
    def __init__(self):
        self.adapter = HTTPAdapter()

    def retry_with_auth(self, auth_header_field, auth_header,
                                   response, args):
        """Attempts to authenticate using HTTP NTLM challenge/response.
        The specific NTLM challenge/response is handled by the subclass"""

        if auth_header in response.request.headers:
            return response

        request = copy_request(response.request)

        # initial auth header with username. will result in challenge
        auth = 'NTLM %s' % self.create_auth_req()
        request.headers[auth_header] = auth

        # we must keep the connection because NTLM authenticates the connection, not single requests
        request.headers["Connection"] = "Keep-Alive"

        # A streaming response breaks authentication.
        # This can be fixed by not streaming this request, which is safe because
        # the returned response3 will still have stream=True set if specified in
        # args. In addition, we expect this request to give us a challenge
        # and not the real content, so the content will be short anyway.
        args_nostream = dict(args, stream=False)
        response2 = self.adapter.send(request, **args_nostream)

        # needed to make NTLM auth compatible with requests-2.3.0
        response2.content

        # this is important for some web applications that store authentication-related info in cookies (it took a long time to figure out)
        if response2.headers.get('set-cookie'):
            request.headers['Cookie'] = response2.headers.get('set-cookie')

        # get the challenge
        auth_header_value = response2.headers[auth_header_field]
        ntlm_header_value = list(filter(lambda s: s.startswith('NTLM '), auth_header_value.split(',')))[0].strip()

        # build response
        request = copy_request(request)
        auth = self.create_challenge_response(ntlm_header_value)
        auth = 'NTLM %s' % auth
        request.headers[auth_header] = auth

        response3 = self.adapter.send(request, **args)

        # Update the history.
        response3.history.append(response)
        response3.history.append(response2)

        return response3

    def response_hook(self, r, **kwargs):

        if r.status_code == 401 and 'ntlm' in r.headers.get('www-authenticate','').lower():
            return self.retry_with_auth('www-authenticate',
                                                   'Authorization', r, kwargs)


        if r.status_code == 407 and 'ntlm' in r.headers.get('proxy-authenticate','').lower():
            return self.retry_with_auth('proxy-authenticate',
                                                   'Proxy-authorization', r,
                                                   kwargs)

        return r

    def __call__(self, r):
        r.register_hook('response', self.response_hook)
        return r

    def create_auth_req(self):
        """Create the authorization request

        Returns
        -------
        out : str
            The NTLM authorization request string which will be passed in the
            request's 'Authorization' header. This string should not contain
            the prefix 'NTLM ' as it will be added in `retry_with_auth`
        """
        raise NotImplementedError('Subclasses must implement create_auth_req')

    def create_challenge_response(self, ntlm_header_value):
        """Create the response to the NTLM challenge

        Parameters
        ----------
        ntlm_header_value : str
            The value of the 'www-authenticate' header,
            with the first 5 characters ("NTLM ") removed.

        Returns
        -------
        out : str
            The NTLM challenge response which will be passed in the
            request's 'Authorization' header. This string should not contain
            the prefix 'NTLM ' as it will be added in `retry_with_auth`
        """
        raise NotImplementedError('Subclasses must implement create_challenge_response')


class SSPIAuth(WinAuth):
    """HTTP SSPI Authentication Handler for Requests. Supports pass-the-hash."""
    def __init__(self, user=None):
        import win32api
        try:
            import sspi
        except ImportError:
            raise Exception("SSPI libraries unavailable")
        if user is None:
            user = win32api.GetUserName()
        self.sspi_client = sspi.ClientAuth("NTLM",user)
        super(SSPIAuth, self).__init__()

    def create_auth_req(self):
        import pywintypes
        output_buffer = None
        error_msg = None
        try:
            error_msg, output_buffer = self.sspi_client.authorize(None)
        except pywintypes.error:
            return None
        auth_req = output_buffer[0].Buffer
        auth_req = base64.b64encode(auth_req)
        return auth_req

    def create_challenge_response(self, ntlm_header_value):
        import pywintypes
        ntlm_header_value = base64.b64decode(ntlm_header_value.split(' ')[1])
        output_buffer = None
        input_buffer = ntlm_header_value
        error_msg = None
        try:
            error_msg, output_buffer = self.sspi_client.authorize(input_buffer)
        except pywintypes.error:
            return None
        response_msg = output_buffer[0].Buffer
        response_msg = base64.b64encode(response_msg)
        return response_msg

class HttpNtlmAuth(WinAuth):
    """HTTP NTLM Authentication Handler for Requests. Supports pass-the-hash."""
    def __init__(self, username, password):
        """
            :username   - Username in 'domain\\username' format
            :password   - Password or hash in "ABCDABCDABCDABCD:ABCDABCDABCDABCD" format.
        """
        if ntlm is None:
            raise Exception("NTLM libraries unavailable")
        #parse the username
        try:
            self.domain, self.username = username.split('\\', 1)
        except ValueError:
            raise ValueError("username should be in 'domain\\username' format.")
        self.domain = self.domain.upper()

        self.password = password
        super(HttpNtlmAuth, self).__init__()

    def create_auth_req(self):
        auth = ntlm.create_NTLM_NEGOTIATE_MESSAGE("%s\\%s" % (self.domain,self.username))
        return auth

    def create_challenge_response(self, ntlm_header_value):
        ServerChallenge, NegotiateFlags = ntlm.parse_NTLM_CHALLENGE_MESSAGE(
            ntlm_header_value[5:]
        )
        auth = ntlm.create_NTLM_AUTHENTICATE_MESSAGE(
            ServerChallenge,
            self.username,
            self.domain,
            self.password,
            NegotiateFlags
        )
        return auth

def copy_request(request):
    """
    Copies a Requests PreparedRequest.
    """
    new_request = PreparedRequest()

    new_request.method = request.method
    new_request.url = request.url
    new_request.body = request.body
    new_request.hooks = request.hooks
    new_request.headers = request.headers.copy()

    return new_request
