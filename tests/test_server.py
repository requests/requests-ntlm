from flask import Flask,request
app = Flask(__name__)


REQUEST_2  = 'NTLM TlRMTVNTUAABAAAAB7IIogYABgA7AAAAEwATACgAAAAFASgKAAAAD1ZQTjE2Lk5FT0hBUFNJUy5ORVRET01BSU4='
RESPONSE_2 = 'NTLM TlRMTVNTUAACAAAADAAMADAAAAAHAgMAESIzRFVmd4gAAAAAAAAAAGIAYgA8AAAARABPAE0AQQBJAE4AAgAMAEQATwBNAEEASQBOAAEADABTAEUAUgBWAEUAUgAEABYAZQB4AGEAbQBwAGwAZQAuAGMAbwBtAAMAJABTAEUAUgBWAEUAUgAuAGUAeABhAG0AcABsAGUALgBjAG8AbQAAAAAA'

REQUEST_3  = 'NTLM TlRMTVNTUAADAAAAGAAYAIoAAAAYABgAogAAAAwADABIAAAAEAAQAFQAAAAmACYAZAAAAAAAAAC6AAAABYKIogUBKAoAAAAPRABPAE0AQQBJAE4AdQBzAGUAcgBuAGEAbQBlAFYAUABOADEANgAuAE4ARQBPAEgAQQBQAFMASQBTAC4ATgBFAFQAdjZeLRQrVhKYDGfQV+ue/u5e9utv9uBNcntONflHEp6lK5ze2uhpNLsj74n1D8WV'

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