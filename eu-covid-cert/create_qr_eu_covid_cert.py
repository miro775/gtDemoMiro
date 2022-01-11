import zlib, base45, cbor, pprint
import qrcode

payload1 = {-260: {1: {'dob': '1887-10-13',
            'nam': {'fn': 'TISO',
                    'fnt': 'TISO',
                    'gn': 'JOZEF',
                    'gnt': 'JOZEF'},
            'v': [{'ci': 'nd2ahm4axr43dtu7bs9enhs32k7f3fxr',
                   'co': 'CZ',
                   'dn': 1,
                   'dt': '2021-05-20',
                   'is': 'Ministry of Health of the Czech Republic',
                   'ma': 'ORG-100030215',
                   'mp': 'EU/1/20/1528',
                   'sd': 2,
                   'tg': '840539006',
                   'vp': '1119349007'}],
            'ver': '1.0.1'}},
 1: 'CZ',
 4: 1654747829,
 6: 1623211829}

payload = {1: 'CZ', 4: 1656675788, 6: 1625139788, -260: {1: {'v': [{'ci': 'BB5WGXQ8PAAFGQ7YAKQKSYFUG75GK54N', 'co': 'CZ', 'dn': 2, 'dt': '2021-07-01', 'is': 'Ministry of Health of the Czech Republic', 'ma': 'ORG-100030215', 'mp': 'EU/1/20/1528', 'sd': 2, 'tg': '840539006', 'vp': '1119349007'}], 'dob': '1974-12-31', 'nam': {'fn': 'JUST', 'gn': 'MIROSLAV', 'fnt': 'JUST', 'gnt': 'MIROSLAV'}, 'ver': '1.0.1'}}}


cbor1 = cbor.dumps( payload )
print('cbor1=')
print(cbor1)

kompres1 = zlib.compress( cbor1 )
print('kompres1=')
print(kompres1)

b45str = base45.b45encode(kompres1)
print('b45str=')
print(b45str)

HC1_str = 'HC1:' + b45str.__str__()
pprint.pprint(HC1_str)

#img = qrcode.make( 'HC1:6BF3Z47080WGVS3QOU-1PVEEJ:8L3IGHBFAJ$-5.AOUCI1SNWVC/$D*D4XC00MG84O2P9L-RK%F2OK$6KXIF0+J3FUHJTNKA37B.OIM*7K04R$MMGJCBN PT1C62KNY6G%SOEZVZAOD1JC-EKH2/7P5H9NA2RAJPSJ6U94GP0P7A77NSRGJ038ME7Q0ILNORK/C*QPZCLR-ORK0R*8RTKM2H:TSY6BIHN6-HHD7F0RH1FR7M+KLN5T4XP7+TB6FZQR-UDOVI5:D**83OV*824ZQ0 R200D%8TAHLMGIG7E3BKS4L82KC5/%O RL674/NSZICDSTYWO74M*OB$3Q-CF7BO:0BPASEJQ0FFTVA' )

# me: img = qrcode.make('HC1:NCFOXN*TS0BI$ZDFRHE*E0 VO%7GUG769Y3S3XHW3Q6R5*F9L7U4FC3K9EXNFAPQHIZC4.OI1RM8ZA*LPVT2L+9G4LF4UGEG%80C0I$6UU6TY2I IG8LOG:D39UT4LS6S:%4YE9/MVEK0*LA/CJ6IAXPMHQ1*P1MX1+ZEOQ1OH6ZK5PVFNXUJRH0LH%Y2 UQ7S7TK24H9-78VNI:RA-CT5-QAQ1.EKAOGK KR+P*$K3$OHBW24FAL86H0YQCIA2IE9WT0K3M9UVZSVV*001HW%8UE9.955B9-NT0 2$$0X4PCY0+-CVYCDEBD0HX2JR$4O1K8KES/F-1JZ.KBIH6JK 3MGEC.-B97U: K/YN8AMNHSI%KZYN25CW74$6C0BP3-S-YNHDMBLE/*BLJ8FT5D75W9AV88H76TE8+FFSXDMGR8*LRM5S+QF4QV.8-RV$4782F5$8YCSD2RA+O* 9B7RAOGF7GV8U*Z0B:VL8S+$C/LRHSC0LV0%G3AODO1.-760K9/S%00SE1D1')
img = qrcode.make('HC1:NCFOXN*TS0BI$ZDFRHE*E0 VO%7GUG769Y3S3XHW3Q6R5*F9L7U4FC3K9EXNFAPQHIZC4.OI1RM8ZA*LPVT2L+9G4LF4UGEG%80C0I$6UU6TY2I IG8LOG:D39UT4LS6S:%4YE9/MVEK0*LA/CJ6IAXPMHQ1*P1MX1+ZEOQ1OH6ZK5PVFNXUJRH0LH%Y2 UQ7S7TK24H9-78VNI:RA-CT5-QAQ1.EKAOGK KR+P*$K3$OHBW24FAL86H0YQCIA2IE9WT0K3M9UVZSVV*001HW%8UE9.955B9-NT0 2$$0X4PCY0+-CVYCDEBD0HX2JR$4O1K8KES/F-1JZ.KBIH6JK 3MGEC.-B97U: K/YN8AMNHSI%KZYN25CW74$6C0BP3-S-YNHDMBLE/*BLJ8FT5D75W9AV88H76TE8+FFSXDMGR8*LRM5S+QF4QV.8-RV$4782F5$8YCSD2RA+O* 9B7RAOGF7GV8U*Z0B:VL8S+$C/LRHSC0LV0%G3AODO1.-760K9/S%00SE1D1')

type(img)  # qrcode.image.pil.PilImage
img.save("some_QR_covid1cert_Miro.png")