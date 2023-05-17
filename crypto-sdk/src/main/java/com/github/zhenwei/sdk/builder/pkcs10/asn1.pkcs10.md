

```
 CertificationRequest ::= SEQUENCE {
        certificationRequestInfo CertificationRequestInfo, --证书申请信息
        signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }}, --私钥签名算法
        signature          BIT STRING --签名值
   }



CertificationRequestInfo ::= SEQUENCE {
     version             INTEGER { v1(0) } (v1,...),
     subject             Name,
     subjectPKInfo   SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
     attributes          [0] Attributes{{ CRIAttributes }}
    }
  
  
  SubjectPublicKeyInfo { ALGORITHM : IOSet} ::= SEQUENCE {
        algorithm        AlgorithmIdentifier {{IOSet}},
        subjectPublicKey BIT STRING
   }
  
    Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
  
    Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
      type    ATTRIBUTE.&amp;id({IOSet}),
      values  SET SIZE(1..MAX) OF ATTRIBUTE.&amp;Type({IOSet}{\@type})
    }


```