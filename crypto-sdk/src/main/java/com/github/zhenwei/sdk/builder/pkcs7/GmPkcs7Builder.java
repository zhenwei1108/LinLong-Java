package com.github.zhenwei.sdk.builder.pkcs7;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1InputStream;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.BEROctetString;
import com.github.zhenwei.core.asn1.BERSequence;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERSet;
import com.github.zhenwei.core.asn1.DERTaggedObject;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.ContentInfo;
import com.github.zhenwei.core.asn1.pkcs.IssuerAndSerialNumber;
import com.github.zhenwei.core.asn1.pkcs.SignedData;
import com.github.zhenwei.core.asn1.pkcs.SignerInfo;
import com.github.zhenwei.core.asn1.pkcs.Version;
import com.github.zhenwei.core.asn1.x500.X500Name;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.Certificate;
import com.github.zhenwei.core.enums.CipherAlgEnum;
import com.github.zhenwei.core.enums.GmPkcs7ContentInfoTypeEnum;
import com.github.zhenwei.core.enums.KeyEnum;
import com.github.zhenwei.core.enums.SignAlgEnum;
import com.github.zhenwei.core.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.core.exception.BaseWeGooException;
import com.github.zhenwei.core.exception.WeGooCryptoException;
import com.github.zhenwei.core.exception.WeGooEnvelopException;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.builder.CipherBuilder;
import com.github.zhenwei.sdk.builder.HashBuilder;
import com.github.zhenwei.sdk.builder.KeyBuilder;
import com.github.zhenwei.sdk.builder.RandomBuilder;
import com.github.zhenwei.sdk.builder.params.DigestParams;
import com.github.zhenwei.sdk.util.ArrayUtils;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

public class GmPkcs7Builder extends AbstractPkcs7Builder {

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
   *
   */
  @Override
  ASN1Encodable genSignedData(byte[] data, SignAlgEnum signAlgEnum, byte[] signature,
      Certificate[] certificates, X509CRL[] crls, boolean isAttach) throws WeGooCryptoException {
    try {
      if (ArrayUtils.isEmpty(certificates)) {
        throw new WeGooEnvelopException("cert can not be null");
      }
      crls = crls == null ? new X509CRL[0] : crls;
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
      ASN1EncodableVector crlVector = new ASN1EncodableVector();
      for (X509CRL crl : crls) {
        crlVector.add(new ASN1InputStream(crl.getEncoded()).readObject());
      }
      DERSet setOfCrls = new DERSet(crlVector);
      //signerInfo
      ASN1EncodableVector signerInfosVector = new ASN1EncodableVector();
      DERSet setOfSignerInfo = new DERSet(signerInfosVector);
      /**
       * SignerInfo ::= SEQUENCE {
       *      version Version, --版本
       *      issuerAndSerialNumber IssuerAndSerialNumber, --签名者，含 certSn，subjectDn
       *      digestAlgorithm DigestAlgorithmIdentifier, --摘要算法
       *      authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL, -- 可选，签名者信息集合
       *      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier, -- 签名算法标识符
       *      encryptedDigest EncryptedDigest, -- 签名数据
       *      unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL --可选，扩展信息，可以填充时间戳标记签名时间
       *      }
       */
      Certificate certificate = certificates[0];
      IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(
          certificate.getSubject(), certificate.getSerialNumber().getPositiveValue());

      AlgorithmIdentifier hashId = new AlgorithmIdentifier(signAlgEnum.getDigestAlgEnum().getOid());

      AlgorithmIdentifier signId = new AlgorithmIdentifier(signAlgEnum.getOid());

      //没有填充 authenticatedAttributes，unauthenticatedAttributes
      //authenticatedAttributes 是原文的hash

      byte[] digest = HashBuilder.digest(signAlgEnum.getDigestAlgEnum(), data,
          DigestParams.getInstance(certificate.getSubjectPublicKeyInfo()));
      SignerInfo signerInfo = new SignerInfo(version, issuerAndSerialNumber, hashId, null,
          signId, new DEROctetString(signature), null);
      signerInfosVector.add(signerInfo);
      return new SignedData(version, digestAlgorithms, contentInfo, setOfCerts, setOfCrls,
          setOfSignerInfo);
    } catch (Exception e) {
      throw new WeGooCryptoException(CryptoExceptionMassageEnum.generate_signed_data_err, e);
    }
  }


  @Override
  ASN1Encodable enveloped(X509Certificate certificate, byte[] data) throws WeGooEnvelopException {
    try {
      ASN1EncodableVector envelopedDataVector = new ASN1EncodableVector();
      ASN1EncodableVector recipientInfosVector = new ASN1EncodableVector();
      ASN1EncodableVector recipientInfoVector = new ASN1EncodableVector();
      ASN1EncodableVector encryptedContentInfoVector = new ASN1EncodableVector();
      ASN1Integer version = new ASN1Integer(0);
      envelopedDataVector.add(version);
      //版本
      recipientInfoVector.add(version);
      IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(
          new X500Name(certificate.getSubjectDN().getName()), certificate.getSerialNumber());
      //序列号
      recipientInfoVector.add(issuerAndSerialNumber);
      //匹配算法标识
      PublicKey publicKey = certificate.getPublicKey();
      String algorithm = publicKey.getAlgorithm();
      //todo 算法oid
      ASN1ObjectIdentifier identifier = GMObjectIdentifiers.sms4_cbc;
      boolean isEc = algorithm.equalsIgnoreCase("EC");
      ASN1ObjectIdentifier p7Oid =
          isEc ? new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.3") : ContentInfo.envelopedData;
      //RSA/SM2加解密算法
      AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(identifier);
      recipientInfoVector.add(algorithmIdentifier);
      WeGooProvider provider = new WeGooProvider();
      KeyBuilder keyBuilder = new KeyBuilder(provider);
      Key key = keyBuilder.buildKey(KeyEnum.SM4_128);
      //加密
      byte[] encData = CipherBuilder.cipher(CipherAlgEnum.SM2, publicKey, key.getEncoded(), null,
          true);
      recipientInfoVector.add(new DEROctetString(encData));

      DERSequence recipientInfo = new DERSequence(recipientInfoVector);
      recipientInfosVector.add(recipientInfo);

      DERSet recipientInfos = new DERSet(recipientInfosVector);
      //recipientInfos
      envelopedDataVector.add(recipientInfos);
      //ContentType
      encryptedContentInfoVector.add(
          isEc ? new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.1") : ContentInfo.data);
      //contentEncryptionAlgorithm
      CipherAlgEnum encAlg = CipherAlgEnum.SM4_ECB_PKCS7Padding;
      ASN1ObjectIdentifier sms4_ecb = GMObjectIdentifiers.sms4_ecb;
      byte[] iv = null;
      if (encAlg.getModeEnum().isNeedIV()) {
        //todo
        iv = RandomBuilder.genRandom(16);
        encryptedContentInfoVector.add(new AlgorithmIdentifier(sms4_ecb, new DEROctetString(
            iv)));
      } else {
        encryptedContentInfoVector.add(new AlgorithmIdentifier(sms4_ecb));
      }
      //todo iv
      byte[] symEncData = CipherBuilder.cipher(encAlg, key, data, iv, true);
      // encryptedContent
      encryptedContentInfoVector.add(new DERTaggedObject(false, 0, new BEROctetString(symEncData)));

//        DERSequence encryptedContentInfo = new DERSequence(encryptedContentInfoVector);
      BERSequence encryptedContentInfo = new BERSequence(encryptedContentInfoVector);
      //encryptedContentInfo
      envelopedDataVector.add(encryptedContentInfo);
      //envelopedData
      DERSequence envelopedData = new DERSequence(envelopedDataVector);
      return new ContentInfo(p7Oid, envelopedData);
    } catch (BaseWeGooException e) {
      throw new WeGooEnvelopException(CryptoExceptionMassageEnum.gen_pkcs7_err, e);
    }
  }
}
