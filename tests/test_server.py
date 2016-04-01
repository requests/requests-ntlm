from flask import Flask,request
from ntlm3 import ntlm
app = Flask(__name__)

REQUEST_2_TEMPLATE = '{0} %s' % ntlm.create_NTLM_NEGOTIATE_MESSAGE("domain\\username").decode('ascii')

RESPONSE_2_NONCE = 'TlRMTVNTUAACAAAADAAMADAAAAAHAgMAESIzRFVmd4gAAAAAAAAAAGIAYgA8AAAARABPAE0AQQBJAE4AAgAMAEQATwBNAEEASQBOAAEADABTAEUAUgBWAEUAUgAEABYAZQB4AGEAbQBwAGwAZQAuAGMAbwBtAAMAJABTAEUAUgBWAEUAUgAuAGUAeABhAG0AcABsAGUALgBjAG8AbQAAAAAA'
RESPONSE_2_TEMPLATE = '{0} %s' % RESPONSE_2_NONCE

ServerChallenge, NegotiateFlags = ntlm.parse_NTLM_CHALLENGE_MESSAGE(RESPONSE_2_NONCE)

REQUEST_3_TEMPLATE = '{0} %s' % ntlm.create_NTLM_AUTHENTICATE_MESSAGE(ServerChallenge, 'username', 'domain', 'password', NegotiateFlags).decode('ascii')

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
    response_headers = {'WWW-Authenticate':auth_type if not advertise_nego_and_ntlm else 'Negotiate, NTLM'}
    status_code = 401
    response = "auth with 'domain\\username':'password'"

    # 2nd request
    if request.headers.get('Authorization','') == REQUEST_2_TEMPLATE.format(auth_type):
        response_headers = {'WWW-Authenticate':RESPONSE_2_TEMPLATE.format(auth_type)}
        status_code = 401

    # 3rd request
    elif request.headers.get('Authorization','') == REQUEST_3_TEMPLATE.format(auth_type):
        response_headers = {}
        status_code = 200
        response = "authed"

    return response,status_code,response_headers

if __name__ == "__main__":
    app.run()
