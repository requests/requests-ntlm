import base64
import unittest
import warnings

import requests

import requests_ntlm
from tests.test_utils import domain, password, password_md4, username


class TestRequestsNtlm(unittest.TestCase):

    def setUp(self):
        self.test_server_url = "http://localhost:5000/"
        self.test_server_username = "%s\\%s" % (domain, username)
        self.test_server_password = password
        self.auth_types = ["ntlm", "negotiate", "both"]
        self.hash = password_md4

    def test_requests_ntlm(self):
        for auth_type in self.auth_types:
            res = requests.get(
                url=self.test_server_url + auth_type,
                auth=requests_ntlm.HttpNtlmAuth(
                    self.test_server_username, self.test_server_password
                ),
            )

            self.assertEqual(res.status_code, 200, msg="auth_type " + auth_type)

    def test_requests_ntlm_hash(self):
        # Test authenticating using an NTLM hash
        for auth_type in self.auth_types:
            res = requests.get(
                url=self.test_server_url + auth_type,
                auth=requests_ntlm.HttpNtlmAuth(
                    self.test_server_username, "0" * 32 + ":" + self.hash
                ),
            )

            self.assertEqual(res.status_code, 200, msg="auth_type " + auth_type)

    def test_history_is_preserved(self):
        for auth_type in self.auth_types:
            res = requests.get(
                url=self.test_server_url + auth_type,
                auth=requests_ntlm.HttpNtlmAuth(
                    self.test_server_username, self.test_server_password
                ),
            )

            self.assertEqual(len(res.history), 2)

    def test_new_requests_are_used(self):
        for auth_type in self.auth_types:
            res = requests.get(
                url=self.test_server_url + auth_type,
                auth=requests_ntlm.HttpNtlmAuth(
                    self.test_server_username, self.test_server_password
                ),
            )

            self.assertTrue(res.history[0].request is not res.history[1].request)
            self.assertTrue(res.history[0].request is not res.request)

    def test_permissions_denied(self):
        auth = requests_ntlm.HttpNtlmAuth(
            self.test_server_username,
            self.test_server_password,
        )

        with self.assertRaises(PermissionError) as e:
            requests.get(
                url=f"{self.test_server_url}no_challenge",
                auth=auth,
            )

        self.assertEqual(
            str(e.exception),
            "Access denied: Server did not respond with NTLM challenge token",
        )


class TestCertificateHash(unittest.TestCase):

    def test_rsa_md5(self):
        cert_der = (
            b"MIIDGzCCAgOgAwIBAgIQJzshhViMG5hLHIJHxa+TcTANBgkqhkiG9w0"
            b"BAQQFADAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA4MD"
            b"MxNloXDTE4MDUzMDA4MjMxNlowFTETMBEGA1UEAwwKU0VSVkVSMjAxN"
            b"jCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN9N5GAzI7uq"
            b"AVlI6vUqhY5+EZWCWWGRwR3FT2DEXE5++AiJxXO0i0ZfAkLu7UggtBe"
            b"QwVNkaPD27EYzVUhy1iDo37BrFcLNpfjsjj8wVjaSmQmqvLvrvEh/BT"
            b"C5SBgDrk2+hiMh9PrpJoB3QAMDinz5aW0rEXMKitPBBiADrczyYrliF"
            b"AlEU6pTlKEKDUAeP7dKOBlDbCYvBxKnR3ddVH74I5T2SmNBq5gzkbKP"
            b"nlCXdHLZSh74USu93rKDZQF8YzdTO5dcBreJDJsntyj1o49w9WCt6M7"
            b"+pg6vKvE+tRbpCm7kXq5B9PDi42Nb6//MzNaMYf9V7v5MHapvVSv3+y"
            b"sCAwEAAaNnMGUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGA"
            b"QUFBwMCBggrBgEFBQcDATAVBgNVHREEDjAMggpTRVJWRVIyMDE2MB0G"
            b"A1UdDgQWBBTh4L2Clr9ber6yfY3JFS3wiECL4DANBgkqhkiG9w0BAQQ"
            b"FAAOCAQEA0JK/SL7SP9/nvqWp52vnsxVefTFehThle5DLzagmms/9gu"
            b"oSE2I9XkQIttFMprPosaIZWt7WP42uGcZmoZOzU8kFFYJMfg9Ovyca+"
            b"gnG28jDUMF1E74KrC7uynJiQJ4vPy8ne7F3XJ592LsNJmK577l42gAW"
            b"u08p3TvEJFNHy2dBk/IwZp0HIPr9+JcPf7v0uL6lK930xHJHP56XLzN"
            b"YG8vCMpJFR7wVZp3rXkJQUy3GxyHPJPjS8S43I9j+PoyioWIMEotq2+"
            b"q0IpXU/KeNFkdGV6VPCmzhykijExOMwO6doUzIUM8orv9jYLHXYC+i6"
            b"IFKSb6runxF1MAik+GCSA=="
        )

        expected_hash = (
            "2334B8476CBF4E6DFC766A5D5A30D6649C01BAE1662A5C3A130" "2A968D7C6B0F6"
        )
        actual_hash = requests_ntlm.requests_ntlm._get_certificate_hash(
            base64.b64decode(cert_der)
        )
        assert actual_hash == base64.b16decode(expected_hash)

    def test_rsa_sha1(self):
        cert_der = (
            b"MIIDGzCCAgOgAwIBAgIQJg/Mf5sR55xApJRK+kabbTANBgkqhkiG9w0"
            b"BAQUFADAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA4MD"
            b"MxNloXDTE4MDUzMDA4MjMxNlowFTETMBEGA1UEAwwKU0VSVkVSMjAxN"
            b"jCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALPKwYikjbzL"
            b"Lo6JtS6cyytdMMjSrggDoTnRUKauC5/izoYJd+2YVR5YqnluBJZpoFp"
            b"hkCgFFohUOU7qUsI1SkuGnjI8RmWTrrDsSy62BrfX+AXkoPlXo6IpHz"
            b"HaEPxjHJdUACpn8QVWTPmdAhwTwQkeUutrm3EOVnKPX4bafNYeAyj7/"
            b"AGEplgibuXT4/ehbzGKOkRN3ds/pZuf0xc4Q2+gtXn20tQIUt7t6iwh"
            b"nEWjIgopFL/hX/r5q5MpF6stc1XgIwJjEzqMp76w/HUQVqaYneU4qSG"
            b"f90ANK/TQ3aDbUNtMC/ULtIfHqHIW4POuBYXaWBsqalJL2VL3YYkKTU"
            b"sCAwEAAaNnMGUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGA"
            b"QUFBwMCBggrBgEFBQcDATAVBgNVHREEDjAMggpTRVJWRVIyMDE2MB0G"
            b"A1UdDgQWBBS1jgojcjPu9vqeP1uSKuiIonGwAjANBgkqhkiG9w0BAQU"
            b"FAAOCAQEAKjHL6k5Dv/Zb7dvbYEZyx0wVhjHkCTpT3xstI3+TjfAFsu"
            b"3zMmyFqFqzmr4pWZ/rHc3ObD4pEa24kP9hfB8nmr8oHMLebGmvkzh5h"
            b"0GYc4dIH7Ky1yfQN51hi7/X5iN7jnnBoCJTTlgeBVYDOEBXhfXi3cLT"
            b"u3d7nz2heyNq07gFP8iN7MfqdPZndVDYY82imLgsgar9w5d+fvnYM+k"
            b"XWItNNCUH18M26Obp4Es/Qogo/E70uqkMHost2D+tww/7woXi36X3w/"
            b"D2yBDyrJMJKZLmDgfpNIeCimncTOzi2IhzqJiOY/4XPsVN/Xqv0/dzG"
            b"TDdI11kPLq4EiwxvPanCg=="
        )

        expected_hash = (
            "14CFE8E4B332B20A343FC840B18F9F6F78926AFE7EC3E7B8E28" "969619B1E8F3E"
        )
        actual_hash = requests_ntlm.requests_ntlm._get_certificate_hash(
            base64.b64decode(cert_der)
        )
        assert actual_hash == base64.b16decode(expected_hash)

    def test_rsa_sha256(self):
        cert_der = (
            b"MIIDGzCCAgOgAwIBAgIQWkeAtqoFg6pNWF7xC4YXhTANBgkqhkiG9w0"
            b"BAQsFADAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUyNzA5MD"
            b"I0NFoXDTE4MDUyNzA5MjI0NFowFTETMBEGA1UEAwwKU0VSVkVSMjAxN"
            b"jCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALIPKM5uykFy"
            b"NmVoLyvPSXGk15ZDqjYi3AbUxVFwCkVImqhefLATit3PkTUYFtAT+TC"
            b"AwK2E4lOu1XHM+Tmp2KIOnq2oUR8qMEvfxYThEf1MHxkctFljFssZ9N"
            b"vASDD4lzw8r0Bhl+E5PhR22Eu1Wago5bvIldojkwG+WBxPQv3ZR546L"
            b"MUZNaBXC0RhuGj5w83lbVz75qM98wvv1ekfZYAP7lrVyHxqCTPDomEU"
            b"I45tQQZHCZl5nRx1fPCyyYfcfqvFlLWD4Q3PZAbnw6mi0MiWJbGYKME"
            b"1XGicjqyn/zM9XKA1t/JzChS2bxf6rsyA9I7ibdRHUxsm1JgKry2jfW"
            b"0CAwEAAaNnMGUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGA"
            b"QUFBwMCBggrBgEFBQcDATAVBgNVHREEDjAMggpTRVJWRVIyMDE2MB0G"
            b"A1UdDgQWBBQabLGWg1sn7AXPwYPyfE0ER921ZDANBgkqhkiG9w0BAQs"
            b"FAAOCAQEAnRohyl6ZmOsTWCtxOJx5A8yr//NweXKwWWmFQXRmCb4bMC"
            b"xhD4zqLDf5P6RotGV0I/SHvqz+pAtJuwmr+iyAF6WTzo3164LCfnQEu"
            b"psfrrfMkf3txgDwQkA0oPAw3HEwOnR+tzprw3Yg9x6UoZEhi4XqP9AX"
            b"R49jU92KrNXJcPlz5MbkzNo5t9nr2f8q39b5HBjaiBJxzdM1hxqsbfD"
            b"KirTYbkUgPlVOo/NDmopPPb8IX8ubj/XETZG2jixD0zahgcZ1vdr/iZ"
            b"+50WSXKN2TAKBO2fwoK+2/zIWrGRxJTARfQdF+fGKuj+AERIFNh88HW"
            b"xSDYjHQAaFMcfdUpa9GGQ=="
        )

        expected_hash = (
            "996F3EEA812C1870E30549FF9B86CD87A890B6D8DFDF4A81BEF" "9675970DADB26"
        )
        actual_hash = requests_ntlm.requests_ntlm._get_certificate_hash(
            base64.b64decode(cert_der)
        )
        assert actual_hash == base64.b16decode(expected_hash)

    def test_rsa_sha384(self):
        cert_der = (
            b"MIIDGzCCAgOgAwIBAgIQEmj1prSSQYRL2zYBEjsm5jANBgkqhkiG9w0"
            b"BAQwFADAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA4MD"
            b"MxN1oXDTE4MDUzMDA4MjMxN1owFTETMBEGA1UEAwwKU0VSVkVSMjAxN"
            b"jCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKsK5NvHi4xO"
            b"081fRLMmPqKsKaHvXgPRykLA0SmKxpGJHfTAZzxojHVeVwOm87IvQj2"
            b"JUh/yrRwSi5Oqrvqx29l2IC/qQt2xkAQsO51/EWkMQ5OSJsl1MN3NXW"
            b"eRTKVoUuJzBs8XLmeraxQcBPyyLhq+WpMl/Q4ZDn1FrUEZfxV0POXgU"
            b"dI3ApuQNRtJOb6iteBIoQyMlnof0RswBUnkiWCA/+/nzR0j33j47IfL"
            b"nkmU4RtqkBlO13f6+e1GZ4lEcQVI2yZq4Zgu5VVGAFU2lQZ3aEVMTu9"
            b"8HEqD6heyNp2on5G/K/DCrGWYCBiASjnX3wiSz0BYv8f3HhCgIyVKhJ"
            b"8CAwEAAaNnMGUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGA"
            b"QUFBwMCBggrBgEFBQcDATAVBgNVHREEDjAMggpTRVJWRVIyMDE2MB0G"
            b"A1UdDgQWBBQS/SI61S2UE8xwSgHxbkCTpZXo4TANBgkqhkiG9w0BAQw"
            b"FAAOCAQEAMVV/WMXd9w4jtDfSrIsKaWKGtHtiMPpAJibXmSakBRwLOn"
            b"5ZGXL2bWI/Ac2J2Y7bSzs1im2ifwmEqwzzqnpVKShIkZmtij0LS0SEr"
            b"6Fw5IrK8tD6SH+lMMXUTvp4/lLQlgRCwOWxry/YhQSnuprx8IfSPvil"
            b"kwZ0Ysim4Aa+X5ojlhHpWB53edX+lFrmR1YWValBnQ5DvnDyFyLR6II"
            b"Ialp4vmkzI9e3/eOgSArksizAhpXpC9dxQBiHXdhredN0X+1BVzbgzV"
            b"hQBEwgnAIPa+B68oDILaV0V8hvxrP6jFM4IrKoGS1cq0B+Ns0zkG7ZA"
            b"2Q0W+3nVwSxIr6bd6hw7g=="
        )

        expected_hash = (
            "34F303C995286F4B214A9BA6435B69B51ECF3758EABC2A14D7A"
            "43FD237DC2B1A1AD9111C5C965E107507CB4198C09FEC"
        )
        actual_hash = requests_ntlm.requests_ntlm._get_certificate_hash(
            base64.b64decode(cert_der)
        )
        assert actual_hash == base64.b16decode(expected_hash)

    def test_rsa_sha512(self):
        cert_der = (
            b"MIIDGzCCAgOgAwIBAgIQUDHcKGevZohJV+TkIIYC1DANBgkqhkiG9w0"
            b"BAQ0FADAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA4MD"
            b"MxN1oXDTE4MDUzMDA4MjMxN1owFTETMBEGA1UEAwwKU0VSVkVSMjAxN"
            b"jCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKr9bo/XXvHt"
            b"D6Qnhb1wyLg9lDQxxe/enH49LQihtVTZMwGf2010h81QrRUe/bkHTvw"
            b"K22s2lqj3fUpGxtEbYFWLAHxv6IFnIKd+Zi1zaCPGfas9ekqCSj3vZQ"
            b"j7lCJVGUGuuqnSDvsed6g2Pz/g6mJUa+TzjxN+8wU5oj5YVUK+aing1"
            b"zPSA2MDCfx3+YzjxVwNoGixOz6Yx9ijT4pUsAYQAf1o9R+6W1/IpGgu"
            b"oax714QILT9heqIowwlHzlUZc1UAYs0/JA4CbDZaw9hlJyzMqe/aE46"
            b"efqPDOpO3vCpOSRcSyzh02WijPvEEaPejQRWg8RX93othZ615MT7dqp"
            b"ECAwEAAaNnMGUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGA"
            b"QUFBwMCBggrBgEFBQcDATAVBgNVHREEDjAMggpTRVJWRVIyMDE2MB0G"
            b"A1UdDgQWBBTgod3R6vejt6kOASAApA19xIG6kTANBgkqhkiG9w0BAQ0"
            b"FAAOCAQEAVfz0okK2bh3OQE8cWNbJ5PjJRSAJEqVUvYaTlS0Nqkyuaj"
            b"gicP3hb/pF8FvaVaB6r7LqgBxyW5NNL1xwdNLt60M2zaULL6Fhm1vzM"
            b"sSMc2ynkyN4++ODwii674YcQAnkUh+ZGIx+CTdZBWJfVM9dZb7QjgBT"
            b"nVukeFwN2EOOBSpiQSBpcoeJEEAq9csDVRhEfcB8Wtz7TTItgOVsilY"
            b"dQY56ON5XszjCki6UA3GwdQbBEHjWF2WERqXWrojrSSNOYDvxM5mrEx"
            b"sG1npzUTsaIr9w8ty1beh/2aToCMREvpiPFOXnVV/ovHMU1lFQTNeQ0"
            b"OI7elR0nJ0peai30eMpQQ=="
        )

        expected_hash = (
            "556E1C1784E3B957370B7F544F62C533CB2CA5C1DAE0706FAEF"
            "00544E1AD2B76FF25CFBE69B1C4E630C3BB0207DF11314C6738"
            "BCAED7E071D7BFBF2C9DFAB85D"
        )
        actual_hash = requests_ntlm.requests_ntlm._get_certificate_hash(
            base64.b64decode(cert_der)
        )
        assert actual_hash == base64.b16decode(expected_hash)

    def test_ecdsa_sha1(self):
        cert_der = (
            b"MIIBjjCCATSgAwIBAgIQRCJw7nbtvJ5F8wikRmwgizAJBgcqhkjOPQQ"
            b"BMBUxEzARBgNVBAMMClNFUlZFUjIwMTYwHhcNMTcwNTMwMDgwMzE3Wh"
            b"cNMTgwNTMwMDgyMzE3WjAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MFkwE"
            b"wYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk3fOh178kRglmnPKe9K/mbgi"
            b"gf8YgNq62rF2EpfzpyQY0eGw4xnmKDG73aZ+ATSlV2IybxiUVsKyMUn"
            b"LhPfvmaNnMGUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQ"
            b"UFBwMCBggrBgEFBQcDATAVBgNVHREEDjAMggpTRVJWRVIyMDE2MB0GA"
            b"1UdDgQWBBQSK8qwmiQmyAWWya3FxQDj9wqQAzAJBgcqhkjOPQQBA0kA"
            b"MEYCIQCiOsP56Iqo+cHRvCp2toj65Mgxo/PQY1tn+S3WH4RJFQIhAJe"
            b"gGQuaPWg6aCWV+2+6pNCNMdg/Nix+mMOJ88qCBNHi"
        )

        expected_hash = (
            "1EC9AD46DEE9340E4503CFFDB5CD810CB26B778F46BE95D5EAF" "999DCB1C45EDA"
        )
        actual_hash = requests_ntlm.requests_ntlm._get_certificate_hash(
            base64.b64decode(cert_der)
        )
        assert actual_hash == base64.b16decode(expected_hash)

    def test_ecdsa_sha256(self):
        cert_der = (
            b"MIIBjzCCATWgAwIBAgIQeNQTxkMgq4BF9tKogIGXUTAKBggqhkjOPQQ"
            b"DAjAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA4MDMxN1"
            b"oXDTE4MDUzMDA4MjMxN1owFTETMBEGA1UEAwwKU0VSVkVSMjAxNjBZM"
            b"BMGByqGSM49AgEGCCqGSM49AwEHA0IABDAfXTLOaC3ElgErlgk2tBlM"
            b"wf9XmGlGBw4vBtMJap1hAqbsdxFm6rhK3QU8PFFpv8Z/AtRG7ba3UwQ"
            b"prkssClejZzBlMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBg"
            b"EFBQcDAgYIKwYBBQUHAwEwFQYDVR0RBA4wDIIKU0VSVkVSMjAxNjAdB"
            b"gNVHQ4EFgQUnFDE8824TYAiBeX4fghEEg33UgYwCgYIKoZIzj0EAwID"
            b"SAAwRQIhAK3rXA4/0i6nm/U7bi6y618Ci2Is8++M3tYIXnEsA7zSAiA"
            b"w2s6bJoI+D7Xaey0Hp0gkks9z55y976keIEI+n3qkzw=="
        )

        expected_hash = (
            "FECF1B2585449990D9E3B2C92D3F597EC8354E124EDA751D948" "37C2C89A2C155"
        )
        actual_hash = requests_ntlm.requests_ntlm._get_certificate_hash(
            base64.b64decode(cert_der)
        )
        assert actual_hash == base64.b16decode(expected_hash)

    def test_ecdsa_sha384(self):
        cert_der = (
            b"MIIBjzCCATWgAwIBAgIQcO3/jALdQ6BOAoaoseLSCjAKBggqhkjOPQQ"
            b"DAzAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA4MDMxOF"
            b"oXDTE4MDUzMDA4MjMxOFowFTETMBEGA1UEAwwKU0VSVkVSMjAxNjBZM"
            b"BMGByqGSM49AgEGCCqGSM49AwEHA0IABJLjZH274heB/8PhmhWWCIVQ"
            b"Wle1hBZEN3Tk2yWSKaz9pz1bjwb9t79lVpQE9tvGL0zP9AqJYHcVOO9"
            b"YG9trqfejZzBlMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBg"
            b"EFBQcDAgYIKwYBBQUHAwEwFQYDVR0RBA4wDIIKU0VSVkVSMjAxNjAdB"
            b"gNVHQ4EFgQUkRajoFr8qZ/8L8rKB3zGiGolDygwCgYIKoZIzj0EAwMD"
            b"SAAwRQIgfi8dAxXljCMSvngtDtagGCTGBs7Xxh8Z3WX6ZwJZsHYCIQC"
            b"D4iNReh1afXKYC0ipjXWAIkiihnEEycCIQMbkMNst7A=="
        )

        expected_hash = (
            "D2987AD8F20E8316A831261B74EF7B3E55155D0922E07FFE546"
            "20806982B68A73A5E3C478BAA5E7714135CB26D980749"
        )
        actual_hash = requests_ntlm.requests_ntlm._get_certificate_hash(
            base64.b64decode(cert_der)
        )
        assert actual_hash == base64.b16decode(expected_hash)

    def test_ecdsa_sha512(self):
        cert_der = (
            b"MIIBjjCCATWgAwIBAgIQHVj2AGEwd6pOOSbcf0skQDAKBggqhkjOPQQ"
            b"DBDAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA3NTUzOV"
            b"oXDTE4MDUzMDA4MTUzOVowFTETMBEGA1UEAwwKU0VSVkVSMjAxNjBZM"
            b"BMGByqGSM49AgEGCCqGSM49AwEHA0IABL8d9S++MFpfzeH8B3vG/PjA"
            b"AWg8tGJVgsMw9nR+OfC9ltbTUwhB+yPk3JPcfW/bqsyeUgq4//LhaSp"
            b"lOWFNaNqjZzBlMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBg"
            b"EFBQcDAgYIKwYBBQUHAwEwFQYDVR0RBA4wDIIKU0VSVkVSMjAxNjAdB"
            b"gNVHQ4EFgQUKUkCgLlxoeai0EtQrZth1/BSc5kwCgYIKoZIzj0EAwQD"
            b"RwAwRAIgRrV7CLpDG7KueyFA3ZDced9dPOcv2Eydx/hgrfxYEcYCIBQ"
            b"D35JvzmqU05kSFV5eTvkhkaDObd7V55vokhm31+Li"
        )

        expected_hash = (
            "E5CB68B2F843D63BF40BCB2007608F8197618392783F2330E5E"
            "F19A5BD8F0B2FAAC861855FBB63A221CC46FC1E226A072411AF"
            "175DDE479281E006878B348059"
        )
        actual_hash = requests_ntlm.requests_ntlm._get_certificate_hash(
            base64.b64decode(cert_der)
        )
        assert actual_hash == base64.b16decode(expected_hash)

    def test_invalid_signature_algorithm(self):
        # Manually edited from test_ecdsa_sha512 to change the OID to '1.2.840.10045.4.3.5'
        cert_der = (
            b"MIIBjjCCATWgAwIBAgIQHVj2AGEwd6pOOSbcf0skQDAKBggqhkjOPQQ"
            b"DBTAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA3NTUzOV"
            b"oXDTE4MDUzMDA4MTUzOVowFTETMBEGA1UEAwwKU0VSVkVSMjAxNjBZM"
            b"BMGByqGSM49AgEGCCqGSM49AwEHA0IABL8d9S++MFpfzeH8B3vG/PjA"
            b"AWg8tGJVgsMw9nR+OfC9ltbTUwhB+yPk3JPcfW/bqsyeUgq4//LhaSp"
            b"lOWFNaNqjZzBlMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBg"
            b"EFBQcDAgYIKwYBBQUHAwEwFQYDVR0RBA4wDIIKU0VSVkVSMjAxNjAdB"
            b"gNVHQ4EFgQUKUkCgLlxoeai0EtQrZth1/BSc5kwCgYIKoZIzj0EAwUD"
            b"RwAwRAIgRrV7CLpDG7KueyFA3ZDced9dPOcv2Eydx/hgrfxYEcYCIBQ"
            b"D35JvzmqU05kSFV5eTvkhkaDObd7V55vokhm31+Li"
        )

        expected_hash = None
        expected_warning = (
            "Failed to get signature algorithm from "
            "certificate, unable to pass channel bindings:"
        )

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            actual_hash = requests_ntlm.requests_ntlm._get_certificate_hash(
                base64.b64decode(cert_der)
            )
            assert actual_hash == expected_hash
            assert expected_warning in str(w[-1].message)
