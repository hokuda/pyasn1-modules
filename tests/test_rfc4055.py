#
# This file is part of pyasn1-modules software.
#
# Created by Russ Housley
# Modified by Russ Housley to add OAEPwithPSSCertificateTestCase
# Copyright (c) 2019-2021, Vigil Security, LLC
# License: http://snmplabs.com/pyasn1/license.html
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import univ

from pyasn1_modules import pem
from pyasn1_modules import rfc5280
from pyasn1_modules import rfc4055


class PSSDefautTestCase(unittest.TestCase):
    pss_default_pem_text = "MAsGCSqGSIb3DQEBCg=="

    def setUp(self):
        self.asn1Spec = rfc5280.AlgorithmIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pss_default_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertTrue(rfc4055.id_RSASSA_PSS, asn1Object[0])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pss_default_pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertFalse(asn1Object['parameters'].hasValue())


class PSSSHA512TestCase(unittest.TestCase):
    pss_sha512_pem_text = "MDwGCSqGSIb3DQEBCjAvoA8wDQYJYIZIAWUDBAIDBQChHDAaBg" \
                          "kqhkiG9w0BAQgwDQYJYIZIAWUDBAIDBQA="

    def setUp(self):
        self.asn1Spec = rfc5280.AlgorithmIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pss_sha512_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertTrue(rfc4055.id_RSASSA_PSS, asn1Object[0])
        self.assertEqual(substrate, der_encoder(asn1Object))

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pss_sha512_pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertTrue(asn1Object['parameters'].hasValue())
        self.assertTrue(20, asn1Object['parameters']['saltLength'])


class OAEPDefautTestCase(unittest.TestCase):
    oaep_default_pem_text = "MAsGCSqGSIb3DQEBBw=="

    def setUp(self):
        self.asn1Spec = rfc5280.AlgorithmIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.oaep_default_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertTrue(rfc4055.id_RSAES_OAEP, asn1Object[0])
        self.assertEqual(substrate, der_encoder(asn1Object))

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.oaep_default_pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertFalse(asn1Object['parameters'].hasValue())


class OAEPSHA256TestCase(unittest.TestCase):
    oaep_sha256_pem_text = "MDwGCSqGSIb3DQEBBzAvoA8wDQYJYIZIAWUDBAIBBQChHDAaB" \
                           "gkqhkiG9w0BAQgwDQYJYIZIAWUDBAIBBQA="

    def setUp(self):
        self.asn1Spec = rfc5280.AlgorithmIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.oaep_sha256_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertTrue(rfc4055.id_RSAES_OAEP, asn1Object[0])
        self.assertEqual(substrate, der_encoder(asn1Object))

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.oaep_sha256_pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertTrue(asn1Object['parameters'].hasValue())

        oaep_p = asn1Object['parameters']

        self.assertEqual(univ.Null(""), oaep_p['hashFunc']['parameters'])
        self.assertEqual(univ.Null(""),
            oaep_p['maskGenFunc']['parameters']['parameters'])


class OAEPFullTestCase(unittest.TestCase):
    oaep_full_pem_text = "MFMGCSqGSIb3DQEBBzBGoA8wDQYJYIZIAWUDBAICBQChHDAaBgk" \
                         "qhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiFTATBgkqhkiG9w0BAQ" \
                         "kEBmZvb2Jhcg=="

    def setUp(self):
        self.asn1Spec = rfc5280.AlgorithmIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.oaep_full_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertTrue(rfc4055.id_RSAES_OAEP, asn1Object[0])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.oaep_full_pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertTrue(asn1Object['parameters'].hasValue())
        oaep_p = asn1Object['parameters']
        self.assertEqual(univ.Null(""), oaep_p['hashFunc']['parameters'])
        self.assertEqual(
            univ.Null(""), oaep_p['maskGenFunc']['parameters']['parameters'])
        self.assertEqual(
            univ.OctetString(value='foobar'),
            oaep_p['pSourceFunc']['parameters'])

class OAEPwithPSSCertificateTestCase(unittest.TestCase):
    cert_pem_text = """\
MIIFTjCCBAWgAwIBAgIUXUvoaK4HRF8l+bU15F9ZuK8egh4wPgYJKoZIhvcNAQEK
MDGgDTALBglghkgBZQMEAgGhGjAYBgkqhkiG9w0BAQgwCwYJYIZIAWUDBAIBogQC
AgDeMD8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRv
bjERMA8GA1UECgwIQm9ndXMgQ0EwHhcNMjEwMTE4MTgxNjAwWhcNMjMwMTE4MTgx
NjAwWjBNMQswCQYDVQQGEwJVUzELMAkGA1UECAwCVkExEDAOBgNVBAcMB0hlcm5k
b24xEDAOBgNVBAoMB0V4YW1wbGUxDTALBgNVBAMMBEphbmUwggE3MCIGCSqGSIb3
DQEBBzAVohMwEQYJKoZIhvcNAQEJBARUQ1BBA4IBDwAwggEKAoIBAQC84Bo/Rod9
WKSxmNo0EoCPmGBqE2Xl2Le5bJWjc094mawUdqVZaxJ//5VfkewdJxQPk7DbMUvQ
bnhV8nR3D9F8n9dk5aZw7sLcGn5CmmHo3gWB/DoXEoAgB71lQiJuitgQ5UYvBd3Q
hB/gxHOc4pATSeIApYVD1BiLkzio91PoE5QzpxY8r+dq62eH2Xq4WunEmzgT7fT0
bYxlozWcClgt7ll3OtWLPZfuxNOUWtQtPsQV/ejD1BBWmficRmc7640NBDM6GogV
/aKeIYt/xD52G2rqWXVoRt4K2qAWIw8/I9eGT98T10IxNrtTEgUY6YPJb7WETCz2
TSpUrfmrS+XdAgMBAAGjggG7MIIBtzB6BgNVHSMEczBxgBTOXvQVxwhUsNIbmFx1
T/0b58iww6FDpEEwPzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAlZBMRAwDgYDVQQH
DAdIZXJuZG9uMREwDwYDVQQKDAhCb2d1cyBDQYIUGV9AXrKBfdZlq+dKtftqaLF5
2U8wDAYDVR0TAQH/BAIwADAbBgNVHREEFDASgRBqYW5lQGV4YW1wbGUuY29tMDQG
CCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZXhhbXBsZS5j
b20vMEIGCWCGSAGG+EIBDQQ1FjNUaGlzIGNlcnRpZmljYXRlIGNhbm5vdCBiZSB0
cnVzdGVkIGZvciBhbnkgcHVycG9zZS4wgZMGA1UdCQSBizCBiDA6BgNVBDQxMzAL
MAkGBSsOAwIaBQAwJDAiBgkqhkiG9w0BAQcwFaITMBEGCSqGSIb3DQEBCQQEVENQ
QTAWBgVngQUCEDENMAsMAzEuMgIBAgIBAzAyBgVngQUCEjEpMCcBAf+gAwoBAaED
CgEAogMKAQCjEDAOFgMzLjEKAQQKAQIBAf8BAf8wPgYJKoZIhvcNAQEKMDGgDTAL
BglghkgBZQMEAgGhGjAYBgkqhkiG9w0BAQgwCwYJYIZIAWUDBAIBogQCAgDeA4IB
AQAzXjowG5inwoZSP+OMmCDAPfKES7J17nIslrT31g5ix+MbnPwdFK2m+lon8KEm
tSUb02evRwenVGyAkIxxV5VNHscRZqHDkN/HYdtd4A9zeZkr3wXMZnarjkHNSqmC
F/fpG2L9TKywVfo1cYpSIeWPC8xaNZiXORkMHj5EL460TmaGba07MTYbRhXISlm9
+EqltPo4r54OA6MghmywXQVzyp14PbyOplhm41+kmLY5O6hYXs/sSt62v1oLJlJX
qwK4NmZQh0ByQOD/MLh2oeTaNGTU+J6JPy9+qQojRiC5MeMGtPoehAQBSFWTiynm
OM8nAO5K54L6ipEULLVSSjXt
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.cert_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        spki = asn1Object['tbsCertificate']['subjectPublicKeyInfo']
        self.assertEqual(rfc4055.id_RSAES_OAEP, spki['algorithm']['algorithm'])
        self.assertTrue(spki['algorithm']['parameters'].hasValue())

        oaep_p, rest = der_decoder(spki['algorithm']['parameters'],
            asn1Spec=rfc4055.RSAES_OAEP_params())

        self.assertFalse(rest)
        self.assertTrue(oaep_p.prettyPrint())
        self.assertEqual(spki['algorithm']['parameters'], der_encoder(oaep_p))

        self.assertEqual(
            rfc4055.id_pSpecified, oaep_p['pSourceFunc']['algorithm'])
        self.assertTrue(oaep_p['pSourceFunc']['parameters'].hasValue())

        psf_p, rest = der_decoder(oaep_p['pSourceFunc']['parameters'],
            asn1Spec=univ.OctetString())

        self.assertFalse(rest)
        self.assertTrue(psf_p.prettyPrint())
        self.assertEqual(
            oaep_p['pSourceFunc']['parameters'], der_encoder(psf_p))

        self.assertEqual(psf_p, univ.OctetString(value='TCPA'))

        sig = asn1Object['tbsCertificate']['signature']
        self.assertEqual(rfc4055.id_RSASSA_PSS, sig['algorithm'])
        self.assertTrue(sig['parameters'].hasValue())

        pss_p, rest = der_decoder(
            sig['parameters'], asn1Spec=rfc4055.RSASSA_PSS_params())

        self.assertFalse(rest)
        self.assertTrue(pss_p.prettyPrint())
        self.assertEqual(sig['parameters'], der_encoder(pss_p))

        self.assertEqual(222, pss_p['saltLength'])
        self.assertEqual(
            rfc4055.id_mgf1, pss_p['maskGenAlgorithm']['algorithm'])
        self.assertTrue(pss_p['maskGenAlgorithm']['parameters'].hasValue())

        mgf_p, rest = der_decoder(
            pss_p['maskGenAlgorithm']['parameters'],
            asn1Spec=rfc4055.MaskGenAlgorithm())

        self.assertFalse(rest)
        self.assertTrue(mgf_p.prettyPrint())
        self.assertEqual(
            pss_p['maskGenAlgorithm']['parameters'], der_encoder(mgf_p))

        self.assertEqual(rfc4055.id_sha256, mgf_p['algorithm'])
        self.assertFalse(mgf_p['parameters'].hasValue())

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.cert_pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        spki = asn1Object['tbsCertificate']['subjectPublicKeyInfo']
        self.assertEqual(rfc4055.id_RSAES_OAEP, spki['algorithm']['algorithm'])

        oaep_p = spki['algorithm']['parameters']
        self.assertEqual(
            rfc4055.id_pSpecified, oaep_p['pSourceFunc']['algorithm'])

        psf_p = oaep_p['pSourceFunc']['parameters']
        self.assertEqual(psf_p, univ.OctetString(value='TCPA'))

        sig = asn1Object['tbsCertificate']['signature']
        self.assertEqual(rfc4055.id_RSASSA_PSS, sig['algorithm'])
        self.assertEqual(222, sig['parameters']['saltLength'])

        mgf = sig['parameters']['maskGenAlgorithm']
        self.assertEqual(rfc4055.id_mgf1, mgf['algorithm'])
        self.assertEqual(rfc4055.id_sha256, mgf['parameters']['algorithm'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
