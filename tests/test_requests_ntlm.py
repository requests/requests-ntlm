import unittest
import requests
import requests_ntlm


class TestRequestsNtlm(unittest.TestCase):

    def setUp(self):
        self.test_server_url        = 'http://localhost:5000/'
        self.test_server_username   = 'domain\\username'
        self.test_server_password   = 'password'
        self.auth_types = ['ntlm','negotiate','both']

    def test_requests_ntlm(self):
        for auth_type in self.auth_types:
            res = requests.get(\
                url  = self.test_server_url + auth_type,\
                auth = requests_ntlm.HttpNtlmAuth(
                    self.test_server_username,\
                    self.test_server_password))

            self.assertEqual(res.status_code,200, msg='auth_type ' + auth_type)

    def test_history_is_preserved(self):
        for auth_type in self.auth_types:
            res = requests.get(url=self.test_server_url + auth_type,
                               auth=requests_ntlm.HttpNtlmAuth(self.test_server_username,
                                                               self.test_server_password))

            self.assertEqual(len(res.history), 2)

    def test_new_requests_are_used(self):
        for auth_type in self.auth_types:
            res = requests.get(url=self.test_server_url + auth_type,
                               auth=requests_ntlm.HttpNtlmAuth(self.test_server_username,
                                                               self.test_server_password))

            self.assertTrue(res.history[0].request is not res.history[1].request)
            self.assertTrue(res.history[0].request is not res.request)

    def test_unrecognized_authenticate_header(self):
        res = requests.get(url=self.test_server_url + 'basic',
                           auth=requests_ntlm.HttpNtlmAuth(self.test_server_username,
                                                           self.test_server_password))
        self.assertEquals(res.status_code, 401)

    def test_proxy_authenticate(self):
        res = requests.get(url=self.test_server_url + 'proxy_negotiate',
                           auth=requests_ntlm.HttpNtlmAuth(self.test_server_username,
                                                           self.test_server_password))
        self.assertEquals(res.status_code, 200)

if __name__ == '__main__':
    unittest.main()