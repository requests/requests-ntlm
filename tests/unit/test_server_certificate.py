import unittest
import mock

from binascii import unhexlify
from requests_ntlm import requests_ntlm

# A hex string of a DER encoded certificate
certificate_byte_string = unhexlify('308203BC30820325A003020102020900C6C70409BC225BA0300D06092A864886F70D0101050500'
                                    '30819B310B3009060355040613024A50310E300C06035504081305546F6B796F3110300E060355'
                                    '040713074368756F2D6B753111300F060355040A13084672616E6B34444431183016060355040B'
                                    '130F5765624365727420537570706F7274311830160603550403130F4672616E6B344444205765'
                                    '622043413123302106092A864886F70D0109011614737570706F7274406672616E6B3464642E63'
                                    '6F6D301E170D3037313230373130323134365A170D3137313230343130323134365A30819B310B'
                                    '3009060355040613024A50310E300C06035504081305546F6B796F3110300E0603550407130743'
                                    '68756F2D6B753111300F060355040A13084672616E6B34444431183016060355040B130F576562'
                                    '4365727420537570706F7274311830160603550403130F4672616E6B3444442057656220434131'
                                    '23302106092A864886F70D0109011614737570706F7274406672616E6B3464642E636F6D30819F'
                                    '300D06092A864886F70D010101050003818D0030818902818100BBAFBC8F25D5E60CBDBFF8BDA2'
                                    'A20C50ACB30BFB5D04C0063D9494421C63EA489F227FBB5EAA75E016BE8C004882C1370BBE4E21'
                                    'D54C4BAC35E6C68A1E80D835CF1FCE3836DC73EF927C508699F9708FFC232E9611C0F82EC7BFD0'
                                    '220AD4AB3B23D87B5D44577E58F543E003AD63D827C6335716955ED739A0026FD414B74C7B0203'
                                    '010001A382010430820100301D0603551D0E0416041462F37BED06D4B1D59C7F48E5EFC5C91561'
                                    'FDD9113081D00603551D230481C83081C5801462F37BED06D4B1D59C7F48E5EFC5C91561FDD911'
                                    'A181A1A4819E30819B310B3009060355040613024A50310E300C06035504081305546F6B796F31'
                                    '10300E060355040713074368756F2D6B753111300F060355040A13084672616E6B344444311830'
                                    '16060355040B130F5765624365727420537570706F7274311830160603550403130F4672616E6B'
                                    '344444205765622043413123302106092A864886F70D0109011614737570706F7274406672616E'
                                    '6B3464642E636F6D820900C6C70409BC225BA0300C0603551D13040530030101FF300D06092A86'
                                    '4886F70D010105050003818100BA2C2E91DDB85398DF4C0A4B6590DF64734608746563652D7587'
                                    '910626CD31CDA24C182F2D3019F22ACC3D68BCB3230EE3CC0B73019903E0F3385DF81636B20461'
                                    '81D1019985938B0EF57992CB988FDE7506EED73EAB39725BF047A0B9B24D9184DCBB1B0A2E28C8'
                                    '7C90E72B69E8A8FB74DE9B8912C071A2C375E173C484810E0A')

# The SHA256 hash of the DER encoded certificate above
expected_cert_hash = 'AFED3DEC06DA16D94856C6EC6863B2D9D514395E7EAB446B69167C2D7E240908'

host_port_info = {'default': 443,
                  'override': 1234}

# Check the port used for the connection
def mock_connect(host_port):
    host = host_port[0]
    port = host_port[1]
    expected_port = host_port_info[host]

    assert port == expected_port

    return ''

def mock_getpeercert(ignore):
    return certificate_byte_string

class TestServerCertCheck(unittest.TestCase):
    # HTTP tests, no certificate should be returned
    def test_get_server_cert_http_no_prefix(self):
        test_url = 'override:1234/endpoint'
        expected = None
        actual = requests_ntlm._get_server_cert(test_url)

        assert actual == expected

    def test_get_server_cert_full_http(self):
        test_url = 'http://override:1234/endpoint'
        expected = None
        actual = requests_ntlm._get_server_cert(test_url)

        assert actual == expected

    def test_get_server_cert_http_no_port(self):
        test_url = 'http://default/endpoint'
        expected = None
        actual = requests_ntlm._get_server_cert(test_url)

        assert actual == expected

    def test_get_server_cert_http_no_endpoint(self):
        test_url = 'http://override:1234'
        expected = None
        actual = requests_ntlm._get_server_cert(test_url)

        assert actual == expected

    # HTTPS tests, need to mock out system functions
    @mock.patch('ssl.SSLSocket.connect', side_effect=mock_connect)
    @mock.patch('ssl.SSLSocket.getpeercert', side_effect=mock_getpeercert)
    def test_get_server_cert_full_https(self, connect_function, getpeercert_function):
        test_url = 'https://override:1234/endpoint'
        expected = expected_cert_hash
        actual = requests_ntlm._get_server_cert(test_url)

        assert actual == expected

    @mock.patch('ssl.SSLSocket.connect', side_effect=mock_connect)
    @mock.patch('ssl.SSLSocket.getpeercert', side_effect=mock_getpeercert)
    def test_get_server_cert_https_no_port(self, connect_function, getpeercert_function):
        test_url = 'https://default/endpoint'
        expected = expected_cert_hash
        actual = requests_ntlm._get_server_cert(test_url)

        assert actual == expected

    @mock.patch('ssl.SSLSocket.connect', side_effect=mock_connect)
    @mock.patch('ssl.SSLSocket.getpeercert', side_effect=mock_getpeercert)
    def test_get_server_cert_https_no_endpoint(self, connect_function, getpeercert_function):
        test_url = 'https://override:1234'
        expected = expected_cert_hash
        actual = requests_ntlm._get_server_cert(test_url)

        assert actual == expected