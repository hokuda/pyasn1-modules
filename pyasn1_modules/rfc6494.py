#
# This file is part of pyasn1-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2020, Vigil Security, LLC
# License: http://snmplabs.com/pyasn1/license.html
#
# Certificate Profile and Certificate Management for
# SEcure Neighbor Discovery (SEND)
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc6494.txt
#

from pyasn1.type import univ

id_kp = univ.ObjectIdentifier('1.3.6.1.5.5.7.3')

id_kp_sendOwner = id_kp + (25, )
id_kp_sendProxiedOwner = id_kp + (26, )
id_kp_sendProxiedRouter = id_kp + (24, )
id_kp_sendRouter = id_kp + (23, )
