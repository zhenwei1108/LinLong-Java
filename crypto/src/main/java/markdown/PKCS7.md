# PKCS7结构简列
* 参考  RFC 2315

```ASN.1

ContentInfo ::= SEQUENCE {
contentType ContentType,
content
[0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }

ContentType ::= OBJECT IDENTIFIER
-- data, signedData, envelopedData, signedAndEnvelopedData, digestedData, and encryptedData

Data ::= OCTET STRING

SignedData ::= SEQUENCE { -- 结构同时间戳
version Version,
digestAlgorithms DigestAlgorithmIdentifiers, (SET) --摘要算法
contentInfo ContentInfo,  (SEQUENCE) -或为原文 若不带原文. 时间戳时此处为TST或 SM2Signature
certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL, --P6扩展证书和X509证书集合
crls [1] IMPLICIT CertificateRevocationLists OPTIONAL, -- 吊销列表
signerInfos SignerInfos --签名这信息
}


DigestAlgorithmIdentifiers ::=  SET OF DigestAlgorithmIdentifier

SignerInfos ::= SET OF SignerInfo

SignerInfo ::= SEQUENCE {
version Version,
issuerAndSerialNumber IssuerAndSerialNumber,
digestAlgorithm DigestAlgorithmIdentifier, --摘要算法
authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL, --原文摘要结果
digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
encryptedDigest EncryptedDigest, --签名值
unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL } --扩展, 可填充时间戳

EncryptedDigest ::= OCTET STRING


DigestInfo ::= SEQUENCE {
digestAlgorithm DigestAlgorithmIdentifier,
digest Digest }

    Digest ::= OCTET STRING




EnvelopedData ::= SEQUENCE {
version Version,
recipientInfos RecipientInfos,
encryptedContentInfo EncryptedContentInfo }

    RecipientInfos ::= SET OF RecipientInfo
 
    EncryptedContentInfo ::= SEQUENCE {
      contentType ContentType,
      contentEncryptionAlgorithm
        ContentEncryptionAlgorithmIdentifier,
      encryptedContent
        [0] IMPLICIT EncryptedContent OPTIONAL }
 
    EncryptedContent ::= OCTET STRING


RecipientInfo ::= SEQUENCE {
version Version,
issuerAndSerialNumber IssuerAndSerialNumber,
keyEncryptionAlgorithm

        KeyEncryptionAlgorithmIdentifier,
      encryptedKey EncryptedKey }
 
    EncryptedKey ::= OCTET STRING





SignedAndEnvelopedData ::= SEQUENCE {
version Version,
recipientInfos RecipientInfos,
digestAlgorithms DigestAlgorithmIdentifiers,
encryptedContentInfo EncryptedContentInfo,
certificates
[0] IMPLICIT ExtendedCertificatesAndCertificates
OPTIONAL,
crls
[1] IMPLICIT CertificateRevocationLists OPTIONAL,
signerInfos SignerInfos }


DigestedData ::= SEQUENCE {
version Version,
digestAlgorithm DigestAlgorithmIdentifier,
contentInfo ContentInfo,
digest Digest }

    Digest ::= OCTET STRING



EncryptedData ::= SEQUENCE {
version Version,
encryptedContentInfo EncryptedContentInfo }


pkcs-7 OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) US(840) rsadsi(113549)
pkcs(1) 7 }

    data OBJECT IDENTIFIER ::= { pkcs-7 1 }
    signedData OBJECT IDENTIFIER ::= { pkcs-7 2 }
    envelopedData OBJECT IDENTIFIER ::= { pkcs-7 3 }
    signedAndEnvelopedData OBJECT IDENTIFIER ::=
       { pkcs-7 4 }
    digestedData OBJECT IDENTIFIER ::= { pkcs-7 5 }
    encryptedData OBJECT IDENTIFIER ::= { pkcs-7 6 }

```