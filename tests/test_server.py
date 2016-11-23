import base64
import struct

from flask import Flask,request
from tests.test_utils import domain, username, password

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

def get_auth_response(auth_type, advertise_nego_and_ntlm=False):
    # Set the default responses
    response_headers = {'WWW-Authenticate': auth_type if not advertise_nego_and_ntlm else 'Negotiate, NTLM'}
    status_code = 401
    response = "auth with '%s\\%s':'%s'" % (domain, username, password)

    # Get the actual header that is returned by requests_ntlm
    actual_header = request.headers.get('Authorization', '')

    # Check what the message type is from the header
    if actual_header == '':
        # This is the initial connection, need to return a 401
        message_type = None
    else:
        message_type = get_message_type(auth_type, actual_header)

    # Validate that the message type is either a negotiate or authenticate message and act accordingly
    if message_type == 1:
        # Add the challenge token and return it with the response headers
        challenge_response = ('TlRMTVNTUAACAAAAAwAMADgAAAAzgoriASNFZ4mrze8AAAA'
                              'AAAAAACQAJABEAAAABgBwFwAAAA9TAGUAcgB2AGUAcgACAA'
                              'wARABvAG0AYQBpAG4AAQAMAFMAZQByAHYAZQByAAAAAAA=')
        challenge_header = auth_type + ' ' + challenge_response
        response_headers = {'WWW-Authenticate': challenge_header}
        status_code = 401

    # Server received the authenticate token and validates it matches what we expect
    elif message_type == 3:
        response_headers = {}
        status_code = 200
        response = 'authed'

    return response, status_code, response_headers

def get_message_type(auth_type, header):
    msg = base64.b64decode(header[len(auth_type):])
    signature = msg[0:8]

    # Check first that the message is an actual NTLM message
    if signature != b'NTLMSSP\x00':
        return None
    else:
        return struct.unpack("<I", msg[8:12])[0]


if __name__ == "__main__":
    app.run()
