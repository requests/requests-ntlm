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

    def test_history_is_preserved(self):
        res = requests.get(url=self.test_server_url,
                           auth=requests_ntlm.HttpNtlmAuth(self.test_server_username,
                                                           self.test_server_password))

        self.assertEqual(len(res.history), 2)

    def test_new_requests_are_used(self):
        res = requests.get(url=self.test_server_url,
                           auth=requests_ntlm.HttpNtlmAuth(self.test_server_username,
                                                           self.test_server_password))

        self.assertTrue(res.history[0].request is not res.history[1].request)
        self.assertTrue(res.history[0].request is not res.request)

if __name__ == '__main__':
    unittest.main()