

* 顶级语法
```

PFX ::= SEQUENCE {
       version     INTEGER {v3(3)}(v3,...),
       authSafe    ContentInfo,
       macData     MacData OPTIONAL
   }


MacData ::= SEQUENCE {
       mac         DigestInfo, -- mac信息，算法、mac结果
       macSalt     OCTET STRING, --随机盐
       iterations  INTEGER DEFAULT 1
   }


```


ContentInfo分两种类型

1.  AuthenticatedSafe 身份认证类型
```ASN.1
AuthenticatedSafe ::= SEQUENCE OF ContentInfo
       -- Data if unencrypted
       -- EncryptedData if password-encrypted
       -- EnvelopedData if public key-encrypted

```
2. SafeBag 安全包类型

```ASN.1
SafeContents ::= SEQUENCE OF SafeBag

SafeBag ::= SEQUENCE {
     bagId          BAG-TYPE.&id ({PKCS12BagSet}) -- oid  1.2.840.113549.1.12.10.1.*
     bagValue       [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
     bagAttributes  SET OF PKCS12Attribute OPTIONAL
 }

```


```ASN.1
PKCS12BagSet BAG-TYPE ::= {
       keyBag |
       pkcs8ShroudedKeyBag |
       certBag |
       crlBag |
       secretBag |
       safeContentsBag,
       ...  -- 可以是 AuthenticatedSafe 类型 ps: EncryptedData
   }

1. 
KeyBag ::= PrivateKeyInfo
2. 
PKCS8ShroudedKeyBag ::= EncryptedPrivateKeyInfo

EncryptedPrivateKeyInfo ::= SEQUENCE {
        encryptionAlgorithm  EncryptionAlgorithmIdentifier,
        encryptedData        EncryptedData }
        
EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

EncryptedData ::= OCTET STRING
3. 
CertBag ::= SEQUENCE {
       certId      BAG-TYPE.&id   ({CertTypes}),
       certValue   [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId})
   }

x509Certificate BAG-TYPE ::= {OCTET STRING IDENTIFIED BY {certTypes 1}}

sdsiCertificate BAG-TYPE ::=
       {IA5String IDENTIFIED BY {certTypes 2}}
       
CertTypes BAG-TYPE ::= { x509Certificate | sdsiCertificate, ... -- For future extensions }


4.
CRLBag ::= SEQUENCE {
       crlId      BAG-TYPE.&id  ({CRLTypes}),
       crlValue  [0] EXPLICIT BAG-TYPE.&Type ({CRLTypes}{@crlId})
   }
   
x509CRL BAG-TYPE ::=
       {OCTET STRING IDENTIFIED BY {crlTypes 1}}   
   
CRLTypes BAG-TYPE ::= {
       x509CRL,
       ... -- For future extensions
   }   

5.
SecretBag ::= SEQUENCE {
       secretTypeId   BAG-TYPE.&id ({SecretTypes}),
       secretValue    [0] EXPLICIT BAG-TYPE.&Type ({SecretTypes}
                          {@secretTypeId})
   }

SecretTypes BAG-TYPE ::= {
       ... -- For future extensions
   }


```


```ASN.1

PKCS12Attribute ::= SEQUENCE {
     attrId      ATTRIBUTE.&id ({PKCS12AttrSet}),
     attrValues  SET OF ATTRIBUTE.&Type ({PKCS12AttrSet}{@attrId})
 } -- This type is compatible with the X.500 type 'Attribute'

PKCS12AttrSet ATTRIBUTE ::= {
     friendlyName | -- from PKCS #9 [23]  -- 别名
     localKeyId,    -- from PKCS #9  -- 公钥标识（公钥hash）
     ... -- Other attributes are allowed
 }
```
