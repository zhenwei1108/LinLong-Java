package com.github.zhenwei.sdk.builder.pkcs7;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1InputStream;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSet;
import com.github.zhenwei.core.asn1.pkcs.ContentInfo;
import com.github.zhenwei.core.asn1.pkcs.SignedData;
import com.github.zhenwei.core.asn1.pkcs.SignerInfo;
import com.github.zhenwei.core.asn1.pkcs.Version;
import com.github.zhenwei.core.asn1.x509.Certificate;
import com.github.zhenwei.core.enums.BasePkcs7TypeEnum;
import com.github.zhenwei.core.enums.GmPkcs7ContentInfoTypeEnum;
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
      SignAlgEnum signAlgEnum,
      byte[] signature, Certificate[] certificates, X509CRL[] crls, boolean isAttach)
      throws WeGooCryptoException {
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
      DERSet digestAlgorithms = new DERSet(signAlgEnum.getDigestAlgEnum().getOid());
      if (!isAttach) {
        data = null;
      }
      //若包含原文则填充原文
      ContentInfo contentInfo = genPkcs7ContentInfo(GmPkcs7ContentInfoTypeEnum.DATA, data,
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

  abstract SignerInfo genSignerInfo(ASN1Integer version, Certificate certificate,
      SignAlgEnum signAlgEnum, byte[] digest, byte[] signature);


  abstract ASN1Encodable enveloped(X509Certificate certificate, byte[] data)
      throws WeGooEnvelopException;
}
