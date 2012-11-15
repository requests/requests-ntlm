import unittest
import requests
import requests_ntlm
import test_server

class TestRequestsNtlm(unittest.TestCase):

    def setUp(self):
        self.test_server_url        = 'http://localhost:5000'
        self.test_server_username   = 'domain\\username'
        self.test_server_password   = 'password'

    def test_requests_ntlm(self):
        res = requests.get(\
            url  = self.test_server_url,\
            auth = requests_ntlm.HttpNtlmAuth(
                self.test_server_username,\
                self.test_server_password))

        self.assertEqual(res.status_code,200)

if __name__ == '__main__':
    unittest.main()