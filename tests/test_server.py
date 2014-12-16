from flask import Flask,request
from ntlm3 import ntlm
app = Flask(__name__)

REQUEST_2 = 'NTLM %s' % ntlm.create_NTLM_NEGOTIATE_MESSAGE("domain\\username").decode('ascii')

RESPONSE_2 = 'NTLM TlRMTVNTUAACAAAADAAMADAAAAAHAgMAESIzRFVmd4gAAAAAAAAAAGIAYgA8AAAARABPAE0AQQBJAE4AAgAMAEQATwBNAEEASQBOAAEADABTAEUAUgBWAEUAUgAEABYAZQB4AGEAbQBwAGwAZQAuAGMAbwBtAAMAJABTAEUAUgBWAEUAUgAuAGUAeABhAG0AcABsAGUALgBjAG8AbQAAAAAA'
ServerChallenge, NegotiateFlags = ntlm.parse_NTLM_CHALLENGE_MESSAGE(RESPONSE_2[5:])

REQUEST_3 = 'NTLM %s' % ntlm.create_NTLM_AUTHENTICATE_MESSAGE(ServerChallenge, 'username', 'domain', 'password', NegotiateFlags).decode('ascii')

@app.route("/")
def ntlm_auth():
    response_headers = {'WWW-Authenticate':'NTLM'}
    status_code = 401
    response = "auth with 'domain\\username':'password'"

    # 2nd request
    if request.headers.get('Authorization','') == REQUEST_2:
        response_headers = {'WWW-Authenticate':RESPONSE_2}
        status_code = 401

    # 3rd request
    elif request.headers.get('Authorization','') == REQUEST_3:
        response_headers = {}
        status_code = 200
        response = "authed"

    return response,status_code,response_headers

if __name__ == "__main__":
    app.run()
