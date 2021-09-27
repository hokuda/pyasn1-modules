#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2021, Vigil Security, LLC
# License: http://snmplabs.com/pyasn1/license.html
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_modules import pem
from pyasn1_modules import rfc5280
from pyasn1_modules import rfc8995


class MASAURLCertExtnTestCase(unittest.TestCase):
    pem_text = """\
MIIB5DCCAWqgAwIBAgIEUqTBnTAKBggqhkjOPQQDAjBdMQ8wDQYDVQQGEwZDYW5h
ZGExEDAOBgNVBAgMB09udGFyaW8xEjAQBgNVBAsMCVNhbmRlbG1hbjEkMCIGA1UE
AwwbaGlnaHdheS10ZXN0LmV4YW1wbGUuY29tIENBMCAXDTIxMDQxMzE5NTQzNVoY
DzI5OTkxMjMxMDAwMDAwWjAiMSAwHgYDVQQFDBcwMC0xNi0zZS1mZi1mZS1kMC01
NS1hYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHMxRIayEmeN/ZcDIY9kzhjJ
BFbAqCvfb2tNHZGGwlNTZ0FAnekTG7nR/nin5C2YtK7gjQZjpAy2mtcGa4HZus2j
UTBPMB0GA1UdDgQWBBRl6ZXqHJNdk+spS7Ca2lBFEQijcjAJBgNVHRMEAjAAMCMG
CCsGAQUFBwEgBBcWFW1hc2EuZXhhbXBsZS5jb206MTIzNDAKBggqhkjOPQQDAgNo
ADBlAjB8znDeUpmY+lLdck2So6a/bnVk9dgXRQC5Ie01oPoK57jTESkJ9buE0wCs
xuipt7gCMQDGngI5M3GKrIXC8MdKf0L+62dw5TqCdXMxqlOFIoR8KLqvsWmGyaTx
l0G6K4Tqsw8=
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        found = False
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc8995.id_pe_masa_url:
                extn_value, rest = der_decoder(extn['extnValue'],
                    asn1Spec=rfc5280.certificateExtensionsMap[extn['extnID']])
                self.assertFalse(rest)
                self.assertTrue(extn_value.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(extn_value))
                self.assertIn('masa', extn_value)
                found = True

        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
