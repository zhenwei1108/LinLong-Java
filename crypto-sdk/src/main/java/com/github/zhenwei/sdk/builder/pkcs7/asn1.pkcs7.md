* pkcs7
```ASN.1
ContentInfo ::= SEQUENCE {
     contentType ContentType,
     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
       
ContentType ::= OBJECT IDENTIFIER
可选如下：
```
* Data
```ASN.1
Data ::= OCTET STRING
```

* SignedData

```ASN.1
SignedData ::= SEQUENCE{
        version  Version, --版本 1
        digestAlgorithms DigestAlgorithmIdentifiers, --摘要算法标识符的集合
        contentInfo ContentInfo,-- Data 原文数据，GMT-0010 写错了
        certificates[0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL, --证书集合
        crls[1] IMPLICIT CertificateRevocationLists OPTIONAL, --吊销列表集合
        signerInfos SignerInfos --签名者信息的集合
     }
    
 DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 
 SignerInfos ::= SET OF SignerInfo
 
  SignerInfo ::= SEQUENCE {
        version Version, --版本 1
        issuerAndSerialNumber IssuerAndSerialNumber, --颁发者信息
        digestAlgorithm DigestAlgorithmIdentifier, -- 摘要算法
        authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL, -- 原文摘要或其他签名属性的集合
        digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,  -- 签名算法
        encryptedDigest EncryptedDigest, -- 签名结果
        unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL -- 扩展，未被签名的验证信息，可以是时间戳 
        }
        
      EncryptedDigest ::= OCTET STRING
      

```

* EnvelopedData

```ASN.1
  EnvelopedData ::= SEQUENCE {
        version Version, --版本 1
        recipientInfos RecipientInfos, --接收者信息集合
        encryptedContentInfo EncryptedContentInfo --加密内容 
        }
        
  RecipientInfos ::= SET OF RecipientInfo
      
      
    RecipientInfo ::= SEQUENCE {
        version Version, --版本 1
        issuerAndSerialNumber IssuerAndSerialNumber, --颁发者信息
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier, --加密算法
        encryptedKey EncryptedKey --密钥密文（对称密钥密文） 
        }
     
    EncryptedKey ::= OCTET STRING
      
      
  EncryptedContentInfo ::= SEQUENCE {
        contentType ContentType, --内容类型
        contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier, --加密算法
        encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL  --加密结果（对称加密结果） 
        sharedInfo1 [1] IMPLICIT OCTET STRING OPTIONAL, --协商好的共享信息（国密定义）
        sharedInfo2 [2] IMPLICIT OCTET STRING OPTIONAL, --协商好的共享信息（国密定义）
        }
        
    EncryptedContent ::= OCTET STRING
```

* SignedAndEnvelopedData

```ASN.1
SignedAndEnvelopedData ::= SEQUENCE {
     version Version, --版本 1
     recipientInfos RecipientInfos, --接收者信息
     digestAlgorithms DigestAlgorithmIdentifiers, --摘要算法
     encryptedContentInfo EncryptedContentInfo, -- 加密内容
     certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL, --证书
     crls [1] IMPLICIT CertificateRevocationLists OPTIONAL, --crl
     signerInfos SignerInfos  -- 签名信息
     }

```


```ASN.1
DigestedData ::= SEQUENCE {
     version Version, --版本 0
     digestAlgorithm DigestAlgorithmIdentifier, --摘要算法
     contentInfo ContentInfo, --Data 原文
     digest Digest -- 摘要
     }

```


```ASN.1
EncryptedData ::= SEQUENCE {
    version Version,
    encryptedContentInfo EncryptedContentInfo 
    }
```

```ASN.1
SM2Signature ::={
    R  Integer, --签名值的第一部分
    S  Integer, --签名值的第二部分
    }

```