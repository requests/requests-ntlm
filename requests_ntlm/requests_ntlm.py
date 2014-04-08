from requests.auth import AuthBase
from requests.adapters import HTTPAdapter
from requests.models import PreparedRequest
from ntlm import ntlm


class HttpNtlmAuth(AuthBase):
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
        self.adapter = HTTPAdapter()

    def retry_using_http_NTLM_auth(self, auth_header_field, auth_header,
                                   response, args):
        """Attempts to authenticate using HTTP NTLM challenge/response"""

        if auth_header in response.request.headers:
            return response

        request = copy_request(response.request)
        

        # initial auth header with username. will result in challenge
        auth = 'NTLM %s' % ntlm.create_NTLM_NEGOTIATE_MESSAGE("%s\\%s" % (self.domain,self.username))
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

        # this is important for some web applications that store authentication-related info in cookies (it took a long time to figure out)
        if response2.headers.get('set-cookie'):
            request.headers['Cookie'] = response2.headers.get('set-cookie')

        # get the challenge
        auth_header_value = response2.headers[auth_header_field]
        ntlm_header_value = list(filter(lambda s: s.startswith('NTLM '), auth_header_value.split(',')))[0].strip()
        ServerChallenge, NegotiateFlags = ntlm.parse_NTLM_CHALLENGE_MESSAGE(ntlm_header_value[5:])

        # build response
        request = copy_request(request)
        auth = 'NTLM %s' % ntlm.create_NTLM_AUTHENTICATE_MESSAGE(ServerChallenge, self.username, self.domain, self.password, NegotiateFlags)
        request.headers[auth_header] = auth
        
        response3 = self.adapter.send(request, **args)

        # Update the history.
        response3.history.append(response)
        response3.history.append(response2)

        return response3

    def response_hook(self, r, **kwargs):

        if r.status_code == 401 and 'ntlm' in r.headers.get('www-authenticate','').lower():
            return self.retry_using_http_NTLM_auth('www-authenticate',
                                                   'Authorization', r, kwargs)

        if r.status_code == 407 and 'ntlm' in r.headers.get('proxy-authenticate','').lower():
            return self.retry_using_http_NTLM_auth('proxy-authenticate',
                                                   'Proxy-authorization', r,
                                                   kwargs)

        return r

    def __call__(self, r):
        r.register_hook('response', self.response_hook)
        return r


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
