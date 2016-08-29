import unittest
import requests
import requests_ntlm
import mock

from ..utils import *

"""
In these tests we need to mock out the 4 different methods to ensure timestamp and random nonces return the same value
in all our tests.
"""

class TestRequestsNtlm(unittest.TestCase):

    def setUp(self):
        self.test_server_url        = 'http://localhost:5000/'
        self.test_server_username   = '%s\\%s' % (domain, username)
        self.test_server_password   = password
        self.auth_types = ['ntlm','negotiate','both']

    @mock.patch('os.urandom', side_effect=mock_random)
    @mock.patch('ntlm_auth.messages.get_version', side_effect=mock_version)
    @mock.patch("ntlm_auth.messages.get_random_export_session_key", side_effect=mock_random_session_key)
    @mock.patch('ntlm_auth.compute_response.get_windows_timestamp', side_effect=mock_timestamp)
    def test_requests_ntlm(self, mock_random, mock_version, mock_session_key, mock_timestamp):
        for auth_type in self.auth_types:
            res = requests.get(\
                url  = self.test_server_url + auth_type,\
                auth = requests_ntlm.HttpNtlmAuth(
                    self.test_server_username,\
                    self.test_server_password))

            self.assertEqual(res.status_code,200, msg='auth_type ' + auth_type)

    @mock.patch('os.urandom', side_effect=mock_random)
    @mock.patch('ntlm_auth.messages.get_version', side_effect=mock_version)
    @mock.patch("ntlm_auth.messages.get_random_export_session_key", side_effect=mock_random_session_key)
    @mock.patch('ntlm_auth.compute_response.get_windows_timestamp', side_effect=mock_timestamp)
    def test_history_is_preserved(self, mock_random, mock_version, mock_session_key, mock_timestamp):
        for auth_type in self.auth_types:
            res = requests.get(url=self.test_server_url + auth_type,
                               auth=requests_ntlm.HttpNtlmAuth(self.test_server_username,
                                                               self.test_server_password))

            self.assertEqual(len(res.history), 2)

    @mock.patch('os.urandom', side_effect=mock_random)
    @mock.patch('ntlm_auth.messages.get_version', side_effect=mock_version)
    @mock.patch("ntlm_auth.messages.get_random_export_session_key", side_effect=mock_random_session_key)
    @mock.patch('ntlm_auth.compute_response.get_windows_timestamp', side_effect=mock_timestamp)
    def test_new_requests_are_used(self, mock_random, mock_version, mock_session_key, mock_timestamp):
        for auth_type in self.auth_types:
            res = requests.get(url=self.test_server_url + auth_type,
                               auth=requests_ntlm.HttpNtlmAuth(self.test_server_username,
                                                               self.test_server_password))

            self.assertTrue(res.history[0].request is not res.history[1].request)
            self.assertTrue(res.history[0].request is not res.request)

    def test_username_parse_backslash(self):
        test_user = 'domain\\user'
        expected_domain = 'DOMAIN'
        expected_user = 'user'

        context = requests_ntlm.HttpNtlmAuth(test_user, 'pass')

        actual_domain = context.domain
        actual_user = context.username

        assert actual_domain == expected_domain
        assert actual_user == expected_user

    def test_username_parse_at(self):
        test_user = 'user@domain'
        expected_domain = 'DOMAIN'
        expected_user = 'user'

        context = requests_ntlm.HttpNtlmAuth(test_user, 'pass')

        actual_domain = context.domain
        actual_user = context.username

        assert actual_domain == expected_domain
        assert actual_user == expected_user

    def test_username_parse_no_domain(self):
        test_user = 'user'
        expected_domain = '.'
        expected_user = 'user'

        context = requests_ntlm.HttpNtlmAuth(test_user, 'pass')

        actual_domain = context.domain
        actual_user = context.username

        assert actual_domain == expected_domain
        assert actual_user == expected_user
