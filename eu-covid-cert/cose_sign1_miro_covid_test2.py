
'''

https://blog.hqcodeshop.fi/archives/516-Decoding-EU-Digital-COVID-Certificate.html
https://github.com/HQJaTu/vacdec/tree/certificate-fetch

he code is very short and should provide an easy way to understand how these certificates are encoded:

The QR code encodes a string starting with "HC1:".
The string following "HC1:" is base45 encoded.
Decoding the base45 leads to zlib-compressed data.
Decompression leads to a CBOR Web Token structure.
------------------------------------------------------
Concise Binary Object Representation (CBOR).

CBOR is comparable to JSON, has a superset of JSON’s ability,
but serializes to a binary format which is smaller and faster to generate and parse.
The two primary functions are cbor.loads() and cbor.dumps().


https://pypi.org/project/cbor2/
This library provides encoding and decoding for the Concise Binary Object Representation (CBOR) (RFC 8949) serialization format.
https://datatracker.ietf.org/doc/draft-ietf-cose-rfc8152bis-struct/15/   CBORTag=18 = COSE_Sign1
--------------------------------------------------------


https://pycose.readthedocs.io/en/latest/
https://pycose.readthedocs.io/en/latest/examples.html
https://pycose.readthedocs.io/en/latest/cose/keys/ec2.html

What is COSE?
CBOR Object Signing and Encryption (COSE) is a data format for concise representation of small messages.
It is optimized for low-power devices. COSE messages can be encrypted,
Sign1: A signed COSE message with a single signature.

'''

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

When creating a COSE EC2 Key from a dictionary, you have to make sure that the dictionary holds the KpKty, EC2KpCurve, 
and either EC2KpD (for private COSE EC2 keys) or EC2KpX and EC2KpY (for public COSE EC2 keys) key attributes. 
These attributes are mandatory for a valid COSE EC2 Key. If you don’t specify them, the from_dict() will throw an exception.

# generate a random key ----
cose_key_random = EC2Key.generate_key(crv='P_256')
print("cose_key_random={0}".format(cose_key_random))
# <COSE_Key(EC2Key): {'EC2KpD':  ... (32 B)', 'EC2KpY':  ... (32 B)", 'EC2KpX': , 'EC2KpCurve': 'P256', 'KpKty': 'KtyEC2'}>
print(cose_key_random.keys())

"""

# The key attributes of the COSE EC2 Key can be represented by their string label, the integer identifier or the corresponding python class.

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

"""
# KID: unhexlify(b'7b8947e88e223083')},  # tato informace KID - muj original covid certifikat, odkazuje na CZ - MZCR....
# parsed via "vacdec.py" [https://github.com/HQJaTu/vacdec/tree/certificate-fetch]

{'serialNumber': '00f09d424412274033', 'subject': 'C=CZ, O=MZCR, CN=CZ DSC 1', 'issuer': 'C=CZ, O=MZCR, CN=CZ DSC CSCA 1', 
'notBefore': '2021-05-06T14:24:00.000Z', 'notAfter': '2023-05-06T14:24:00.000Z', 
'signatureAlgorithm': 'RSASSA-PKCS1-v1_5', 'fingerprint': '734c0982d3b2d50ca981a11cf529eb70d89e1478', 
'publicKeyAlgorithm': {'hash': {'name': 'SHA-256'}, 'name': 'ECDSA', 'namedCurve': 'P-256'}, 
'publicKeyPem': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUIzSq5MMYg2oez/kdjVH73ZPmI3lAQZTJsLOGqhJNcahsn+m5vFLeODWFM6/hXQGSL56sIjbKMrYa17lKNAKUw=='}

"""

# COSE Sign1Message
cose_msg2 = Sign1Message(
    phdr = {Algorithm: Es256},
    uhdr = {KID: unhexlify(b'7b8947e88e223083')},  # KID, muj certifikat (cose Sign1) toto ma v unprotected-header  "uhdr"
    key = cose_key_miro
)

"""
https://www.zive.cz/clanky/v-evropskem-ockovacim-qr-kodu-ktery-budete-ukazovat-na-dovolene-se-skryva-zakodovany-text-takhle-ho-prectete/sc-3-a-210469/default.aspx

dob: datum narození
fn: příjmení s diakritikou
fnt: příjmení bez diakritiky
gn: jméno s diakritikou
gnt: jméno bez diakritiky
ci: identifikátor
co: zkratka země (CZ)
dn:  pořadové číslo dávky
dt: datum očkování
is: vydavatel (ministerstvo zdravotnictví)
mp: evropská registrace očkovací látky:
EU/1/20/1528 = Comirnaty
EU/1/20/1507 = Moderna
EU/1/21/1529 = AstraZeneca
EU/1/20/1525 = Janssen
sd: počet dávek
tg: kód nemoci/agensu (840539006)
vp: kód vakcíny (Comirnaty má 1119349007)

4: 1662038147,   ?  Thu Sep 01 2022 13:15:47 GMT+0000
6: 1630502147    ?  Wed Sep 01 2021 13:15:47 GMT+0000

'ci':                'BB5WGXQ8PAAFGQ7YAKQKSYFUG75GK54N'  ,  moje verze 1.0.1
'ci': 'URN:UVCI:01:CZ:YJUECJ77ZGMQ38DT4D2KU9KSBT7DBZQZ'  ,  moje verze 1.3.0

1662136348 =    Fri Sep 02 2022 16:32:28 GMT+0000  [4 nova]
1630607548 = 	Thu Sep 02 2021 18:32:28 GMT+0000  [6 nova]

"""
# Tomas
novy_payload00 = {1: 'CZ', 4: 1662136348, 6: 1630607548, -260: {1: {'v': [
    {'ci': 'URN:UVCI:01:CZ:KR5DFWFGBFMQ34QDVBYRFDTYHJS6D2QZ', 'co': 'CZ', 'dn': 2, 'dt': '2021-07-07',
     'is': 'Ministry of Health of the Czech Republic', 'ma': 'ORG-100030215', 'mp': 'EU/1/20/1528', 'sd': 2,
     'tg': '840539006', 'vp': '1119349007'}], 'dob': '1974-11-28', 'nam': {'fn': 'LANCINGER', 'gn': 'TOMÁŠ', 'fnt': 'LANCINGER',
                                                                           'gnt': 'TOMAS'}, 'ver': '1.3.0'}}}

# babička Lála
novy_payload_babicka = {1: 'CZ', 4: 1662136348, 6: 1630607548, -260: {1: {'v': [
    {'ci': 'URN:UVCI:01:CZ:K4EHFSFQA4HNFBWSAJ6GBDWCU896D2QZ', 'co': 'CZ', 'dn': 2, 'dt': '2021-07-11',
     'is': 'Ministry of Health of the Czech Republic', 'ma': 'ORG-100030215', 'mp': 'EU/1/20/1528', 'sd': 2,
     'tg': '840539006', 'vp': '1119349007'}], 'dob': '1970-10-28', 'nam': {'fn': 'babička', 'gn': 'Lála', 'fnt': 'babicka',
                                                                           'gnt': 'Lala'}, 'ver': '1.3.0'}}}
# Josef Vonasek @ 9.1.1973
novy_payload = {1: 'CZ', 4: 1662136348, 6: 1630607548, -260: {1: {'v': [
    {'ci': 'URN:UVCI:01:CZ:E5EG5SFQS4HFBNWSRS6GRYWCHFS64DQC', 'co': 'CZ', 'dn': 2, 'dt': '2021-07-02',
     'is': 'Ministry of Health of the Czech Republic', 'ma': 'ORG-100030215', 'mp': 'EU/1/20/1528', 'sd': 2,
     'tg': '840539006', 'vp': '1119349007'}], 'dob': '1973-01-09', 'nam': {'fn': 'VONÁŠEK', 'gn': 'JOSEF', 'fnt': 'VONASEK',
                                                                           'gnt': 'JOSEF'}, 'ver': '1.3.0'}}}


# add payload (json) to Cose-message, as CBOR
cose_msg2.payload = cbor2.dumps(novy_payload)

print("cose_msg2={0}".format(cose_msg2))    # cose_msg2=<COSE_Sign1: [{'Algorithm': 'Es256'},...........

# only test, show payload
cbor_payload = cbor2.loads(cose_msg2.payload)
print("cose_msg.payload={0}".format(cbor_payload))
print("eu covid certif., payload as JSON: {0}".format(json.dumps(cbor_payload, indent=2, default=str, ensure_ascii=False)))

#-----  Cose message. endode sign=True, pozor ! fix: # cose.exceptions.CoseIllegalAlgorithm: Conflicting algorithms in key and COSE headers
#----- output obsahuje navic podpis..
cosemsg_encode1 = cose_msg2.encode(tag=True, sign=True)

print("cosemsg_encode1={0}".format(cosemsg_encode1))   # b'\xd2\x84C\xa1\x01&\xa1\x04H{\x89G\xe8\x8e"0\x8...........

print("cbor2.loads={0}".format( cbor2.loads( cosemsg_encode1 ) ) )
# CBORTag(18, [b'\xa1\x01&', {4: b'{\x89G\xe8\x8e"0\x83'}, b'\xa4\x01bCZ\x
# CBORTag=18 = COSE_Sign1

# compress CoseMessage  and  encode Base45....
kompres1 = zlib.compress( cosemsg_encode1 )
b45str = base45.b45encode(kompres1)

print('b45str=')
print(b45str)

#Tomas L, plne meno:
# 6BFOXN*TS0BI$ZDFRHE*E0 VO%7GUG769M*K3XHW3Q6R5.JPBZ0AVDGHH6F2*P5-FJLF6CB9YPD.+IKYJRGK:H3J1D1I3-*TW CXBDOQ3I/S4YC8QS39U19U24T29DPH2NH2FO28.S C2NPT*V2S5TEO2.+I WJ*Q6395J4I-B5ET42HPPEPHCRER3VLIWQHQS6OP6OH6XO9IE5IVU5P2-GA*PE*F6X LEXHQX0$QLF$S8+G.%QESQ0$JW+S-+R2YBV44PZB6H0CJ0RAK:0LPHN6D7LLK*2HG%89UV-0LZ 2S-O:S9UZ4+FJE 4Y3LL/II 0OC9JU0D0HT0HB2PR78+FFZI9$JAQJKMKNK3MZJKJGISKE MCAOI8%M2S9E09W2D218UBRI%K.*N%32/CSW%HT-26ALG%I2S4YZQ H9:EG52IWKP/HLIJLKNF8JF172ARH*Q6:/EI2JA-7MJK4XI6XRP1UQ8WL 6Y.344C+CSI-FH7R76RH%J2ZR+VERT3SOTKNMG/Q$YR4$D$:U. VCQJ$ GZYT+1OB8BLK6V30%W3Q5

# Tomas L , v00
# qrcode.make('HC1:6BFOXN TSMAHN-H V4NO648DJS4JZO92P1AT-%2YVCNX1AVD.JHA:MK1JZZPQA36S4HZ6SH9X5QSDQFY1OSMNV1L8VNF6O MZ1IMPHME13-EUF626IKAV*T6G7ECB66E6U%1I%UN-EIB6-FE0F1SH932QKOJ9ZIHAPZXI$MI1VCSWC%PDB2MN9C.XI/VBKNSYIJGDBGIASJLA8KOHSLOJJPA*70**I-XKN57N*K%1DJQ0K%2C-4XTC/15D-4HRVUMNMD3323R139%HO$9KZ56DE/.QC$Q3J62:6LZ6O59++9-G9+E93ZM$96PZ6+Q6X46+E5+DP:Q67ZMA$6BVU5SI:TU+MMPZ5SZ9BT1X%EPS5 WUQRELS4J1TLSVMSVWWT /KT-KJLV4F7Q0531T178CPI%EGTAHUDBQEAJJKKKMWC8XN8 VV+1639FTZONOEGBQS7A6FIVVVU5AQ3ULOJU6RD5M/ME4TGIO3ENUVCBEWF0$FXTNBKAZT4B4SKLLAX8$XM4NR%6K9*DT:M7:TT40 68Z2

#babicka Lala
# 6BFOXN*TS0BI$ZDFRHE*E0 VO%7GUG769AGJ3XHW3Q6R5.JPBZ0AVDGHH6F2*P5-FJLF6CB9YPD.+IKYJRGK:H3J1D1I3-*TW CXBDOQ380T+USMKS3%T6HTVUSBETKO2X.TV*C19UVH2TQ37ECS5TEO2.+I WJ*Q6395J4I-B5ET42HPPEPHCR7XBGEQAC5ADNPUO8L6IWMW KAHA508XIORW6%5LJL0II5M691BEVH9V3Q721+V5O$97KPA/9Q$95:UENEUW66469363F3HOJ+PB/VSQOL9DLKWCZ3EBKDYGIZ J$XI4OIMEDTJCJKDLEDL9CZTAKBI/8D:8DKTDL+SQ05.$S6ZCJKBRI3U$9LZ68999Q9E$BDZIB7JFZITYI9YKXL7R95526LET5RO4+O8%M7NINBI7LE2KC6LFGD980A19AFT5D75W9AAABG64ZC4N4LI9NE6PE$7I.VCWJS.DF12P95O38IAA43K8URJ4NNB7A2RE/2R%7YEV.LL::M-/VHOAI57QR62IHA4GCGLYBQ7KV6CU9IJ7%6120Z4Q13

#Josef V.
# 6BFOXN*TS0BI$ZDFRHE*E0 VO%7GUG769CIN3XHW3Q6R5.JPBZ0AVDGHH6F2*P5-FJLF6CB9YPD.+IKYJRGK:H3J1D1I3-*TW CXBDOQ350TIVTG-D3%T.33VUSN8TN-2XO3NYD5 3NC3Q.TP$2D0DPH2YZJ WJ*Q6395J4I-B5ET42HPPEPHCR7XB7DOAC5ADNPUO8L6IWMW KAHA508XIORW6%5LJL0II5M691BEVH9V3Q721+V5O$97KPA/9Q$95:UENEUW66469363F3HOJ+PB/VSQOL9DLKWCZ3EBKDYGIZ J$XI4OIMEDTJCJKDLEDL9CZTAKBI/8D:8DKTDL+SQ05.$S6ZCJKB$N3-C3B/L.V99Q9E$BDZIQ4JY8T36F8QUED0DDUC.U-SA CW04B3-SY$NLXEKDM2FMN4F6LF381:YMQ+MN/QP9QE8Q.RO$QAKEPNVVX.OY0W:03D7FVPVPTB*3U-4L.OAERUPYN.LGV%QS3UYWB  EG-9EHG+7CSWO6 SHL525CMZVV0PYJHINI%*H:MAZ4R6U3740AVB33


img1 = qrcode.make('HC1:6BFOXN*TS0BI$ZDFRHE*E0 VO%7GUG769CIN3XHW3Q6R5.JPBZ0AVDGHH6F2*P5-FJLF6CB9YPD.+IKYJRGK:H3J1D1I3-*TW CXBDOQ350TIVTG-D3%T.33VUSN8TN-2XO3NYD5 3NC3Q.TP$2D0DPH2YZJ WJ*Q6395J4I-B5ET42HPPEPHCR7XB7DOAC5ADNPUO8L6IWMW KAHA508XIORW6%5LJL0II5M691BEVH9V3Q721+V5O$97KPA/9Q$95:UENEUW66469363F3HOJ+PB/VSQOL9DLKWCZ3EBKDYGIZ J$XI4OIMEDTJCJKDLEDL9CZTAKBI/8D:8DKTDL+SQ05.$S6ZCJKB$N3-C3B/L.V99Q9E$BDZIQ4JY8T36F8QUED0DDUC.U-SA CW04B3-SY$NLXEKDM2FMN4F6LF381:YMQ+MN/QP9QE8Q.RO$QAKEPNVVX.OY0W:03D7FVPVPTB*3U-4L.OAERUPYN.LGV%QS3UYWB  EG-9EHG+7CSWO6 SHL525CMZVV0PYJHINI%*H:MAZ4R6U3740AVB33')

type(img1)  # qrcode.image.pil.PilImage
img1.save("eu_QR_covid1cert_pepa.png")
