#
# This file is part of pyasn1-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
#
# Copyright (c) 2019, Vigil Security, LLC
# License: http://snmplabs.com/pyasn1/license.html
#
# X.509 Extensions for MUD URL and MUD Signer;
# Object Identifier for CMS Content Type for a MUD file
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc8520.txt
#

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful
from pyasn1_modules import rfc5280


# X.509 Extension for MUD URL

id_pe_mud_url = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.25')

class MUDURLSyntax(char.IA5String):
    pass


# X.509 Extension for MUD Signer

id_pe_mudsigner = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.30')

class MUDsignerSyntax(rfc5280.Name):
    pass


# Object Identifier for CMS Content Type for a MUD file

id_ct_mudtype = univ.ObjectIdentifier('1.2.840.113549.1.9.16.1.41')
