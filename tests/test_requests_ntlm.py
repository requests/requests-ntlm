import unittest
import requests
import requests_ntlm
import test_server

class TestWinAuth(object):
    def setUp(self):
        self.test_server_url        = 'http://localhost:5000'
        self.test_server_username   = 'domain\\username'
        self.test_server_password   = 'password'

    def test_auth(self):
        res = requests.get(
            url=self.test_server_url,
            auth=self.auth
        )
        self.assertEqual(res.status_code,200)

    def test_history_is_preserved(self):
        res = requests.get(
            url=self.test_server_url,
            auth=self.auth
        )
        self.assertEqual(len(res.history), 2)

    def test_new_requests_are_used(self):
        res = requests.get(
            url=self.test_server_url,
            auth=self.auth
        )
        self.assertTrue(res.history[0].request is not res.history[1].request)
        self.assertTrue(res.history[0].request is not res.request)


# TestWinAuth must be first in MRO or its setUp will not run
class TestHttpNtlmAuth(TestWinAuth, unittest.TestCase):

    def setUp(self):
        super(TestHttpNtlmAuth, self).setUp()
        self.auth = requests_ntlm.HttpNtlmAuth(
            self.test_server_username,
            self.test_server_password
        )


class TestSSPIAuth(TestWinAuth, unittest.TestCase):

    def setUp(self):
        super(TestSSPIAuth, self).setUp()
        self.auth = requests_ntlm.SSPIAuth()


if __name__ == '__main__':
    unittest.main()
