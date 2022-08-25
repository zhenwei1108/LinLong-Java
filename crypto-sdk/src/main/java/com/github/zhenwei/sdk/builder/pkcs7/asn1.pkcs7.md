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
SignedData::=SEQUENCE(
        version  Version, --版本 1
        digestAlgorithms DigestAlgorithmIdentifiers, --摘要算法标识符的集合
        contentInfo SM2Signature,--被签名的数据内容，（原文？）
        certificates[0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL, --证书集合
        crls[1] IMPLICIT CertificateRevocationLists OPTIONAL, --吊销列表集合
        signerInfos SignerInfos --签名者信息的集合
     )
    
 DigestAlgorithmIdentifiers::=SET OF DigestAlgorithmIdentifier
 SignerInfos∷ =SET OF SignerInfo
 
  SignerInfo ::= SEQUENCE {
        version Version,
        issuerAndSerialNumber IssuerAndSerialNumber,
        digestAlgorithm DigestAlgorithmIdentifier,
        authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
        digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier, 
        encryptedDigest EncryptedDigest,
        unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL }
        
      EncryptedDigest ::= OCTET STRING
      
 
```

* EnvelopedData

```ASN.1
  EnvelopedData ::= SEQUENCE {
        version Version,
        recipientInfos RecipientInfos,
        encryptedContentInfo EncryptedContentInfo }
        
  RecipientInfos ::= SET OF RecipientInfo
      
      
    RecipientInfo ::= SEQUENCE {
        version Version,
        issuerAndSerialNumber IssuerAndSerialNumber,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        encryptedKey EncryptedKey }
     
    EncryptedKey ::= OCTET STRING
      
      
  EncryptedContentInfo ::= SEQUENCE {
        contentType ContentType,
        contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
        encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
        
    EncryptedContent ::= OCTET STRING
```