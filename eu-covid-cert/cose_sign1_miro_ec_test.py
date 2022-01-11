# https://pycose.readthedocs.io/en/latest/examples.html
# https://pycose.readthedocs.io/en/latest/cose/keys/ec2.html

from binascii import unhexlify, hexlify

import cbor2
import json
import base45, zlib
import qrcode

from cose.messages import Sign1Message, CoseMessage
from cose.keys import CoseKey, EC2Key
from cose.headers import Algorithm, KID
from cose.algorithms import EdDSA
from cose.keys.curves import Ed25519
from cose.keys.keyparam import KpKty, OKPKpD, OKPKpX, KpKeyOps, OKPKpCurve
from cose.keys.keytype import KtyOKP
from cose.keys.keyops import SignOp, VerifyOp

from cose.keys.keytype import KtyEC2
from cose.algorithms import Es256
from cose.keys.curves import P256
from cose.keys.keyparam import KpKty, KpAlg, EC2KpD, EC2KpX, EC2KpY, EC2KpCurve

msg = Sign1Message(
    phdr = {Algorithm: EdDSA, KID: b'kid2'},
    payload = 'signed message'.encode('utf-8'))

print(msg)  #  <COSE_Sign1: [{'Algorithm': 'EdDSA', 'KID': b'kid2'}, {}, b'signe' ... (14 B), b'' ... (0 B)]>

#Sign1Message.



#{'serialNumber': '00f09d424412274033', 'subject': 'C=CZ, O=MZCR, CN=CZ DSC 1', 'issuer': 'C=CZ, O=MZCR, CN=CZ DSC CSCA 1', 'notBefore': '2021-05-06T14:24:00.000Z', 'notAfter': '2023-05-06T14:24:00.000Z', 'signatureAlgorithm': 'RSASSA-PKCS1-v1_5', 'fingerprint': '734c0982d3b2d50ca981a11cf529eb70d89e1478', 'publicKeyAlgorithm': {'hash': {'name': 'SHA-256'}, 'name': 'ECDSA', 'namedCurve': 'P-256'}, 'publicKeyPem': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUIzSq5MMYg2oez/kdjVH73ZPmI3lAQZTJsLOGqhJNcahsn+m5vFLeODWFM6/hXQGSL56sIjbKMrYa17lKNAKUw=='}
#{'crv': 'P-256', 'kid': '7b8947e88e223083', 'kty': 'EC', 'x': 'UIzSq5MMYg2oez_kdjVH73ZPmI3lAQZTJsLOGqhJNcY=', 'y': 'obJ_pubxS3jg1hTOv4V0Bki-erCI2yjK2Gte5SjQClM='}

# create key object from a dict, both the key type and key bytes (KTY and K) are mandatory attributes.
key_attribute_dict = {
    'KTY': 'EC2',
    'CURVE': 'P_256',
    'ALG': 'ES256',
    'D': unhexlify(b'57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3')}

cose_key = CoseKey.from_dict(key_attribute_dict)
print("cose_key={0}".format(cose_key))
# <COSE_Key(EC2Key): {'EC2KpD': "b'W\\xc9 wf' ... (32 B)", 'EC2KpY': "b' \\x13\\x8b\\xf8-' ... (32 B)", 'EC2KpX': "b'\\xba\\xc5\\xb1\\x1c\\xad' ... (32 B)", 'EC2KpCurve': 'P256', 'KpKty': 'KtyEC2', 'KpAlg': 'Es256'}>

#encode/serialize key  , encode() - Encodes the COSE key as a CBOR map
serialized_key = cose_key.encode()
print("serialized_key={0}".format(serialized_key))
# b'\xa6\x01\x02\x03& \x01!X \xba\xc.............................

# deserialize key
print(CoseKey.decode(serialized_key))
# <COSE_Key(EC2Key): {'EC2KpD': "b'W\\xc9 wf' ... (32 B)", 'EC2KpY': "b' \\x13\\x8b\\xf8-' ... (32 B)", 'EC2KpX': "b'\\xba\\xc5\\xb1\\x1c\\xad' ... (32 B)", 'EC2KpCurve': 'P256', 'KpKty': 'KtyEC2', 'KpAlg': 'Es256'}>


# generate a random key -----------------------------------------------------------
cose_key_random = EC2Key.generate_key(crv='P_256')
print("cose_key_random={0}".format(cose_key_random))
# <COSE_Key(EC2Key): {'EC2KpD': 'b\'"B\\x02\\r\\xcb\' ... (32 B)', 'EC2KpY': "b'T\\x91\\xe6\\xcf\\xdc' ... (32 B)", 'EC2KpX': "b'(\\x9a\\xb4ET' ... (32 B)", 'EC2KpCurve': 'P256', 'KpKty': 'KtyEC2'}>

print(cose_key_random.keys())


#-----------------

key_attribute_dict3 = {
    KpKty: KtyEC2,
    EC2KpCurve: P256,
    KpAlg: Es256,
    EC2KpD: unhexlify(b'57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3')}

cose_key3 = CoseKey.from_dict(key_attribute_dict3)
print("cose_key3={0}".format(cose_key3))

#print(unhexlify(b'57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3'))  # b'W\xc9 wfAF\xe8vv\x0c\x95 \xd0T\xaa\x93\xc3\xaf\xb0N0g\x05\xdb`\x900\x85\x07\xb4\xd3'
#print( hexlify(b'W\xc9 wfAF\xe8vv\x0c\x95 \xd0T\xaa\x93\xc3\xaf\xb0N0g\x05\xdb`\x900\x85\x07\xb4\xd3')) # b'57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3'

#-----------------------------------------------

"""
EC2KpX  b'\x17R\xe6!\xfe\xa7\t\n\xc8\x0b\xb4\xbc\x8c:\xd8\\O=Yo\x1dd\xf6Q\xd9p\x9c\xceh\xe74\x88'
EC2KpY  b'\xf2\x1c\xa6\x96\x8e0\xe4\x8bw\x88\xeb\xe3\x85\xe5ofO\xe3\x17\xed\xa5p\xf6E0\xb9\xbe\xf0\xa1J\xf9j'
EC2KpD  b'\x83\xe9\xf1~\xb7\x0fs\xccw\xd8\xc06h\n\xa6\x94\xe0\xfa\xfd\xadv\xd0\xed\xfc\xaa*I\x80D\xd8\xe3c'
x= b'\x17R\xe6!\xfe\xa7\t\n\xc8\x0b\xb4\xbc\x8c:\xd8\\O=Yo\x1dd\xf6Q\xd9p\x9c\xceh\xe74\x88'
y= b'\xf2\x1c\xa6\x96\x8e0\xe4\x8bw\x88\xeb\xe3\x85\xe5ofO\xe3\x17\xed\xa5p\xf6E0\xb9\xbe\xf0\xa1J\xf9j'

print(hexlify(b'\x17R\xe6!\xfe\xa7\t\n\xc8\x0b\xb4\xbc\x8c:\xd8\\O=Yo\x1dd\xf6Q\xd9p\x9c\xceh\xe74\x88'))
print(hexlify(b'\xf2\x1c\xa6\x96\x8e0\xe4\x8bw\x88\xeb\xe3\x85\xe5ofO\xe3\x17\xed\xa5p\xf6E0\xb9\xbe\xf0\xa1J\xf9j'))
print(hexlify(b'\x83\xe9\xf1~\xb7\x0fs\xccw\xd8\xc06h\n\xa6\x94\xe0\xfa\xfd\xadv\xd0\xed\xfc\xaa*I\x80D\xd8\xe3c'))

x = b'1752e621fea7090ac80bb4bc8c3ad85c4f3d596f1d64f651d9709cce68e73488'
y = b'f21ca6968e30e48b7788ebe385e56f664fe317eda570f64530b9bef0a14af96a'
d = b'83e9f17eb70f73cc77d8c036680aa694e0fafdad76d0edfcaa2a498044d8e363'


x=b'E\x9d\xfb\xe5\xd0$_\x87\xeai\xf7\x04,\xca\xfaj\xc5\xea\xc0u\xc9i\xcd@f\x08\x04lmZ\x95\x92'
y=b'\x9co\xbed0f\xd1D\xb0\xaeB\xa1k\xcb\xc65Zlb\xdaR\xd86\x8e\xf5\xf3QW\x01{\xe6?'
d=b"\x0e\xa4\xf6'\xf3\xb6y\xfb\x18\xe3z\x1al\xe3^\xe2\xf7\x1aw\x9b\xfa\xcd\x9d\xd6\x82\xa2\xfa\xa8g:\x87\x18"

When creating a COSE EC2 Key from a dictionary, you have to make sure that the dictionary holds the KpKty, EC2KpCurve, 
and either EC2KpD (for private COSE EC2 keys) or EC2KpX and EC2KpY (for public COSE EC2 keys) key attributes. 
These attributes are mandatory for a valid COSE EC2 Key. If you don’t specify them, the from_dict() will throw an exception.
"""

# muj cert,  kid=b'{\x89G\xe8\x8e"0\x83'
# print(hexlify(b'{\x89G\xe8\x8e"0\x83'))   b'7b8947e88e223083'
# unhexlify(b'7b8947e88e223083')


key_attribute_miro_dict = {
    KpKty: KtyEC2,
    EC2KpCurve: P256,
    KpAlg: Es256,
    EC2KpX: unhexlify(b'1752e621fea7090ac80bb4bc8c3ad85c4f3d596f1d64f651d9709cce68e73488'),
    EC2KpY: unhexlify(b'f21ca6968e30e48b7788ebe385e56f664fe317eda570f64530b9bef0a14af96a'),
    EC2KpD: unhexlify(b'83e9f17eb70f73cc77d8c036680aa694e0fafdad76d0edfcaa2a498044d8e363')
}

cose_key_miro = CoseKey.from_dict(key_attribute_miro_dict)
print("cose_key_miro={0}".format(cose_key_miro))

#cose_key_miro.verify()  #  missing 3 required positional arguments: 'key_type', 'algorithm', and 'key_ops'


novy_payload = {1: 'CZ', 4: 1662038147, 6: 1630502147, -260: {1: {'v': [
    {'ci': 'URN:UVCI:01:CZ:YJUECJ77ZGMQ38DT4D2KU9KSBT7DBZQZ', 'co': 'CZ', 'dn': 2, 'dt': '2021-07-01',
     'is': 'Ministry of Health of the Czech Republic', 'ma': 'ORG-100030215', 'mp': 'EU/1/20/1528', 'sd': 2,
     'tg': '840539006', 'vp': '1119349007'}], 'dob': '1974-11-28', 'nam': {'fn': 'LANC.', 'gn': 'TOMAS', 'fnt': 'LANC.',
                                                                           'gnt': 'TOMAS'}, 'ver': '1.3.0'}}}

# puvodni verze phdr (protected header) phdr = {Algorithm: Es256, KID: b'kid2'},
cose_msg2 = Sign1Message(
    phdr = {Algorithm: Es256},
    uhdr = {KID: unhexlify(b'7b8947e88e223083')},
    key = cose_key_miro
)

cose_msg2.payload = cbor2.dumps(novy_payload)

print("cose_msg2={0}".format(cose_msg2))

cbor_Load = cbor2.loads(cose_msg2.payload)
print("cose_msg.payload={0}".format(cbor_Load))
print("covid Certif. JSON: {0}".format(json.dumps(cbor_Load, indent=2, default=str, ensure_ascii=False)))

#-----  Cose message. endode sign=False , ! no signature !
cosemsg_encode0 = cose_msg2.encode(tag=True, sign=False)
print("cosemsg_encode0={0}".format(cosemsg_encode0))

#-----  Cose message. endode sign=True, pozor ! fix: # cose.exceptions.CoseIllegalAlgorithm: Conflicting algorithms in key and COSE headers
#----- output obsahuje navic podpis..
cosemsg_encode1 = cose_msg2.encode(tag=True, sign=True)
print("cosemsg_encode1={0}".format(cosemsg_encode1))

print("cbor2.loads={0}".format( cbor2.loads( cosemsg_encode1 ) ) )

kompres1 = zlib.compress( cosemsg_encode1 )
print('kompres1=')
print(kompres1)

b45str = base45.b45encode(kompres1)
print('b45str=')
print(b45str)


#-----------------------
img1 = qrcode.make('HC1:6BFOXN TSMAHN-H V4NO648DJS4JZO92P1AT-%2YVCNX1AVD.JHA:MK1JZZPQA36S4HZ6SH9X5QSDQFY1OSMNV1L8VNF6O MZ1IMPHME13-EUF626IKAV*T6G7ECB66E6U%1I%UN-EIB6-FE0F1SH932QKOJ9ZIHAPZXI$MI1VCSWC%PDB2MN9C.XI/VBKNSYIJGDBGIASJLA8KOHSLOJJPA*70**I-XKN57N*K%1DJQ0K%2C-4XTC/15D-4HRVUMNMD3323R139%HO$9KZ56DE/.QC$Q3J62:6LZ6O59++9-G9+E93ZM$96PZ6+Q6X46+E5+DP:Q67ZMA$6BVU5SI:TU+MMPZ5SZ9BT1X%EPS5 WUQRELS4J1TLSVMSVWWT /KT-KJLV4F7Q0531T178CPI%EGTAHUDBQEAJJKKKMWC8XN8 VV+1639FTZONOEGBQS7A6FIVVVU5AQ3ULOJU6RD5M/ME4TGIO3ENUVCBEWF0$FXTNBKAZT4B4SKLLAX8$XM4NR%6K9*DT:M7:TT40 68Z2')

type(img1)  # qrcode.image.pil.PilImage
img1.save("some_QR_covid1cert_Tomas.png")





