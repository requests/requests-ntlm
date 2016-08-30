import requests
import requests_ntlm

username = '.\\User'
password = 'Password01'
http_with_cbt = 'http://127.0.0.1:81/contents.txt'
http_without_cbt = 'http://127.0.0.1:82/contents.txt'
https_with_cbt = 'https://127.0.0.1:441/contents.txt'
https_without_cbt = 'https://127.0.0.1:442/contents.txt'
expected = 'contents'

class Test_Functional():
    def test_ntlm_http_with_cbt(self):
        actual = send_request(http_with_cbt, username, password)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_http_without_cbt(self):
        actual = send_request(http_without_cbt, username, password)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_https_with_cbt(self):
        actual = send_request(https_with_cbt, username, password)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        # Until changes are merged into python-ntlm3 or dependency is changed, this won't work
        assert actual_code == 401

    def test_ntlm_https_without_cbt(self):
        actual = send_request(https_without_cbt, username, password)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

def send_request(url, username, password):
    """
    Sends a request to the url with the credentials specified. Returns the final response
    """
    session = requests.Session()
    session.verify = False
    session.auth = requests_ntlm.HttpNtlmAuth(username, password)
    response = session.get(url)

    return response
