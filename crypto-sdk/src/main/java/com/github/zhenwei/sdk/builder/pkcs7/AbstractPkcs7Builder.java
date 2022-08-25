package com.github.zhenwei.sdk.builder.pkcs7;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1InputStream;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSet;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.Attribute;
import com.github.zhenwei.core.asn1.pkcs.ContentInfo;
import com.github.zhenwei.core.asn1.pkcs.IssuerAndSerialNumber;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.SignedData;
import com.github.zhenwei.core.asn1.pkcs.SignerInfo;
import com.github.zhenwei.core.asn1.pkcs.Version;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.Certificate;
import com.github.zhenwei.core.enums.BasePkcs7TypeEnum;
import com.github.zhenwei.core.enums.GmPkcs7ContentInfoTypeEnum;
import com.github.zhenwei.core.enums.Pkcs7ContentInfoTypeEnum;
import com.github.zhenwei.core.enums.SignAlgEnum;
import com.github.zhenwei.core.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.core.exception.WeGooCryptoException;
import com.github.zhenwei.core.exception.WeGooEnvelopException;
import com.github.zhenwei.sdk.builder.HashBuilder;
import com.github.zhenwei.sdk.builder.params.DigestParams;
import com.github.zhenwei.sdk.util.ArrayUtils;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

public abstract class AbstractPkcs7Builder {

  public ContentInfo genPkcs7ContentInfo(BasePkcs7TypeEnum infoTypeEnum, byte[] data,
      SignAlgEnum signAlgEnum, byte[] signature, Certificate[] certificates, X509CRL[] crls,
      boolean isAttach) throws WeGooCryptoException {
    ASN1Encodable asn1Encodable = null;
    switch (infoTypeEnum.name()) {
      case BasePkcs7TypeEnum.DATA:
        asn1Encodable = genData(data);
        break;
      case BasePkcs7TypeEnum.SIGNED_DATA:
        asn1Encodable = genSignedData(data, signAlgEnum, signature, certificates, crls, isAttach);
        break;
      case BasePkcs7TypeEnum.KEY_AGREEMENT_INFO_DATA:
        break;
      case BasePkcs7TypeEnum.ENCRYPTED_DATA:
        break;
      case BasePkcs7TypeEnum.ENVELOPED_DATA:
        break;
      case BasePkcs7TypeEnum.SIGNED_AND_ENVELOPED_DATA:
        break;
    }
    return new ContentInfo(infoTypeEnum.getOid(), asn1Encodable);
  }

  ASN1Encodable genData(byte[] data) {
    return ArrayUtils.isEmpty(data) ? null : new DEROctetString(data);
  }

  /**
   * @param [data, signAlgEnum, signature, certificates, crls, isAttach]
   *          原文、签名算法、签名证书集合、吊销列表集合、是否包含原文
   * @return com.github.zhenwei.core.asn1.ASN1Encodable
   * @author zhangzhenwei
   * @description GMT-0010
   * @date 2022/8/21  17:55
   * @since: 1.0
   *
   *
   * signedData数据类型结构定义如下:
   * SignedData::=SEQUENCE(
   * version  Version, --版本 1
   * digestAlgorithms DigestAlgorithmIdentifiers, --摘要算法标识符的集合
   * contentInfo SM2Signature,--被签名的数据内容，（原文？）
   * certificates[0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL, --证书集合
   * crls[1] IMPLICIT CertificateRevocationLists OPTIONAL, --吊销列表集合
   * signerInfos SignerInfos --签名者信息的集合
   * )
   *
   * DigestAlgorithmIdentifiers::=SET OF DigestAlgorithmIdentifier
   * SignerInfos∷ =SET OF SignerInfo
   *
   * todo 补充传入原文和私钥的方式
   */
  ASN1Encodable genSignedData(byte[] data, SignAlgEnum signAlgEnum, byte[] signature,
      Certificate[] certificates, X509CRL[] crls, boolean isAttach) throws WeGooCryptoException {
    try {
      if (ArrayUtils.isEmpty(certificates)) {
        throw new WeGooEnvelopException("cert can not be null");
      }
      //version
      Version version = new Version(1);
      //digest algs
      DERSet digestAlgorithms = new DERSet(AlgorithmIdentifier.getInstance(signAlgEnum.getDigestAlgEnum().getOid()));
      if (!isAttach) {
        data = null;
      }
      BasePkcs7TypeEnum pkcs7TypeEnum =
          signAlgEnum == SignAlgEnum.SM3_WITH_SM2 ? GmPkcs7ContentInfoTypeEnum.DATA
              : Pkcs7ContentInfoTypeEnum.DATA;
      //若包含原文则填充原文
      ContentInfo contentInfo = genPkcs7ContentInfo(pkcs7TypeEnum, data,
          signAlgEnum, null, null, null, isAttach);
      //证书集合
      DERSet setOfCerts = new DERSet(certificates);
      //crl 集合
      DERSet setOfCrls = null;
      if (ArrayUtils.notEmpty(crls)) {
        ASN1EncodableVector crlVector = new ASN1EncodableVector();
        for (X509CRL crl : crls) {
          crlVector.add(new ASN1InputStream(crl.getEncoded()).readObject());
        }
        setOfCrls = new DERSet(crlVector);
      }
      Certificate certificate = certificates[0];
      byte[] digest = HashBuilder.digest(signAlgEnum.getDigestAlgEnum(), data,
          DigestParams.getInstance(certificate.getSubjectPublicKeyInfo()));

      //signerInfo
      ASN1EncodableVector signerInfosVector = new ASN1EncodableVector();
      signerInfosVector.add(genSignerInfo(version, certificate, signAlgEnum, digest, signature));
      DERSet setOfSignerInfo = new DERSet(signerInfosVector);
      return new SignedData(version, digestAlgorithms, contentInfo, setOfCerts, setOfCrls,
          setOfSignerInfo);
    } catch (Exception e) {
      throw new WeGooCryptoException(CryptoExceptionMassageEnum.generate_signed_data_err, e);
    }
  }

  /**
   * @param [version, certificate, signAlgEnum, digest, signature]
   * @return com.github.zhenwei.core.asn1.pkcs.SignerInfo
   * @author zhangzhenwei
   * @description
   * SignerInfo ::= SEQUENCE {
   *      version Version,
   *      issuerAndSerialNumber IssuerAndSerialNumber,
   *      digestAlgorithm DigestAlgorithmIdentifier,
   *      authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
   *      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
   *      encryptedDigest EncryptedDigest,
   *      unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL }
   *
   *    EncryptedDigest ::= OCTET STRING
   *
   * @date 2022/8/24  23:14
   * @since: 1.0
   */
  SignerInfo genSignerInfo(ASN1Integer version, Certificate certificate,
      SignAlgEnum signAlgEnum, byte[] digest, byte[] signature) {
    {
      IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(
          certificate.getSubject(), certificate.getSerialNumber().getPositiveValue());
      //todo 是否增加一层sequence
      AlgorithmIdentifier hashId = new AlgorithmIdentifier(signAlgEnum.getDigestAlgEnum().getOid());
      //GMT-0010 要求标识符为： SM2-1， 见GMT-0006：1.2.156.10197.1.301.1
      ASN1ObjectIdentifier asn1ObjectIdentifier =
          signAlgEnum == SignAlgEnum.SM3_WITH_SM2 ? GMObjectIdentifiers.sm2sign
              : PKCSObjectIdentifiers.encryptionAlgorithm;
      AlgorithmIdentifier signId = new AlgorithmIdentifier(asn1ObjectIdentifier);

      // authenticatedAttributes，unauthenticatedAttributes
      //authenticatedAttributes 是原文的hash
      /**
       * 根据RFC 2315 - 9.2描述
       * 如果 authenticatedAttributes存在，必须包含两个属性：
       * 1. PKCS9的 content type
       * 2. PKCS9的 message digest
       * 也可以放入其他属性，例如签名时间
       */

      ASN1EncodableVector vector = new ASN1EncodableVector();
      asn1ObjectIdentifier =
          signAlgEnum == SignAlgEnum.SM3_WITH_SM2 ? GMObjectIdentifiers.data
              : PKCSObjectIdentifiers.data;
      vector.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_contentType,
          new DERSet(asn1ObjectIdentifier)));
      vector.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_messageDigest,
          new DERSet(new DEROctetString(digest))));

      ASN1Set authenticatedAttributes = new DERSet(vector);
      return new SignerInfo(version, issuerAndSerialNumber, hashId,
          authenticatedAttributes, signId, new DEROctetString(signature), null);
    }
  }

  /**
   * @param [certificate, data]
   * @return com.github.zhenwei.core.asn1.ASN1Encodable
   * @author zhangzhenwei
   * @description
   * EnvelopedData ::= SEQUENCE {
   *      version Version,
   *      recipientInfos RecipientInfos,
   *      encryptedContentInfo EncryptedContentInfo }
   *
   *       RecipientInfos ::= SET OF RecipientInfo
   * @date 2022/8/24  22:54
   * @since: 1.0
   */
  ASN1Encodable enveloped(X509Certificate certificate, byte[] data)
      throws WeGooEnvelopException {

  return null;

  }
}
