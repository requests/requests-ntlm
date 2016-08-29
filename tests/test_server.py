import mock

from flask import Flask,request
from ntlm_auth import ntlm
from tests.utils import *

app = Flask(__name__)

@app.route("/ntlm")
def ntlm_auth():
    return get_auth_response('NTLM')

@app.route("/negotiate")
def negotiate_auth():
    return get_auth_response('Negotiate')

@app.route("/both")
def negotiate_and_ntlm_auth():
    return get_auth_response('NTLM', advertise_nego_and_ntlm=True)

# With NTLMv2 we need to mock out some functions that usually return random values to ensure we get the same message
@mock.patch('os.urandom', side_effect=mock_random)
@mock.patch('ntlm_auth.messages.get_version', side_effect=mock_version)
@mock.patch("ntlm_auth.messages.get_random_export_session_key", side_effect=mock_random_session_key)
@mock.patch('ntlm_auth.compute_response.get_windows_timestamp', side_effect=mock_timestamp)
def get_auth_response(auth_type, mock_random, mock_version, mock_session_key, mock_timestamp, advertise_nego_and_ntlm=False):
    # Create the NTLM context on the server for validation with requests_ntlm
    ntlm_context = ntlm.Ntlm()
    negotiate_response = ntlm_context.create_negotiate_message(domain.upper()).decode('ascii')

    challenge_response = 'TlRMTVNTUAACAAAAAwAMADgAAAAzgoriASNFZ4mrze8AAAAAAAAAACQAJABEAAAABgBwFwAAAA9TAGUA' \
                         'cgB2AGUAcgACAAwARABvAG0AYQBpAG4AAQAMAFMAZQByAHYAZQByAAAAAAA='
    ntlm_context.parse_challenge_message(challenge_response)

    auth_response = ntlm_context.create_authenticate_message(username, password, domain.upper()).decode('ascii')

    # Set the default responses
    response_headers = {'WWW-Authenticate': auth_type if not advertise_nego_and_ntlm else 'Negotiate, NTLM'}
    status_code = 401
    response = "auth with '%s\\%s':'%s'" % (domain, username, password)

    # Create the expectation headers to use below
    negotiate_header = auth_type + ' ' + negotiate_response
    challenge_header = auth_type + ' ' + challenge_response
    authenticate_header = auth_type + ' ' + auth_response

    # Get the actual header that is returned by requests_ntlm
    actual_header = request.headers.get('Authorization', '')

    # Server received the negotiate token and validates it matches what we expect
    if actual_header == negotiate_header:
        # Add the challenge token and return it with the response headers
        response_headers = {'WWW-Authenticate': challenge_header}
        status_code = 401

    # Server received the authenticate token and validates it matches what we expect
    elif actual_header == authenticate_header:
        response_headers = {}
        status_code = 200
        response = 'authed'

    return response, status_code, response_headers

if __name__ == "__main__":
    app.run()
