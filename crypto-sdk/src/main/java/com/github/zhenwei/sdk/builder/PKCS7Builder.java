package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.asn1.*;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.*;
import com.github.zhenwei.core.asn1.x500.X500Name;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.Certificate;
import com.github.zhenwei.core.enums.*;
import com.github.zhenwei.core.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.core.exception.BaseWeGooException;
import com.github.zhenwei.core.exception.WeGooCryptoException;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.util.BytesUtil;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

/**
 * @description: P7Builder
 * pkcs 7 构造者， 包含： 签名，信封
 * 参考 RFC-2315(p7) RFC-3852(CMS) / GMT-0010
 * todo 设计大文件编码问题
 * @author: zhangzhenwei
 * @since: 1.0.0
 * @date: 2022/2/28  10:32 下午
 */
public class PKCS7Builder {

    public PKCS7Builder getInstance(Object obj) {
        return null;
    }


    /**
     * @param [typeEnum, data]
     * @return com.github.zhenwei.core.asn1.pkcs.ContentInfo
     * @author zhangzhenwei
     * @description 封装pkcs7
     * 参考 RFC-2315 / GMT-0010
     * ContentInfo ::= SEQUENCE {
     * contentType ContentType,
     * content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
     * @date 2022/3/1  7:27 下午
     * @since: 1.0.0
     */
    public ContentInfo build(BasePkcs7TypeEnum typeEnum, byte[] data, SignAlgEnum signAlgEnum, byte[] signature, Certificate[] certificates, X509CRL[] crls, boolean isAttach) throws WeGooCryptoException {
        ContentInfo contentInfo;
        //根据枚举类型判断是否为国密类型。国密类型OID 有另定义
        if (typeEnum instanceof Pkcs7ContentInfoTypeEnum) {
            Pkcs7ContentInfoTypeEnum infoTypeEnum = (Pkcs7ContentInfoTypeEnum) typeEnum;
            contentInfo = genPkcs7ContentInfo(infoTypeEnum, data);
        } else {//国密相关
            GmPkcs7ContentInfoTypeEnum infoTypeEnum = (GmPkcs7ContentInfoTypeEnum) typeEnum;
            contentInfo = genGmPkcs7ContentInfo(infoTypeEnum, data, signAlgEnum, signature, certificates, crls, isAttach);
        }
        return contentInfo;

    }

    public ContentInfo build(BasePkcs7TypeEnum typeEnum, InputStream inputStream, SignAlgEnum signAlgEnum, byte[] signature, Certificate[] certificates, X509CRL[] crls, boolean isAttach) throws WeGooCryptoException {
        try {
            byte[] data = new byte[inputStream.available()];
            inputStream.read(data);
            return build(typeEnum, data, signAlgEnum, signature, certificates, crls, isAttach);
        } catch (Exception e) {
            throw new WeGooCryptoException(CryptoExceptionMassageEnum.gen_pkcs7_err, e);
        }
    }


    private ContentInfo genPkcs7ContentInfo(Pkcs7ContentInfoTypeEnum infoTypeEnum, byte[] data) throws WeGooCryptoException {
        ASN1Encodable asn1Encodable = null;
        switch (infoTypeEnum) {
            case DATA:
                asn1Encodable = genData(data);
                break;
            case SIGNED_DATA:
                break;
            case DIGESTED_DATA:
                break;
            case ENCRYPTED_DATA:
                break;
            case ENVELOPED_DATA:
                break;
            case SIGNED_AND_ENVELOPED_DATA:
                break;
        }
        return new ContentInfo(infoTypeEnum.getOid(), asn1Encodable);
    }


    private ContentInfo genGmPkcs7ContentInfo(GmPkcs7ContentInfoTypeEnum infoTypeEnum, byte[] data,
                                              SignAlgEnum signAlgEnum, byte[] signature, Certificate[] certificates, X509CRL[] crls, boolean isAttach)
            throws WeGooCryptoException {
        ASN1Encodable asn1Encodable = null;
        switch (infoTypeEnum) {
            case DATA:
                asn1Encodable = genData(data);
                break;
            case SIGNED_DATA:
                asn1Encodable = genSignedData(data, signAlgEnum, signature, certificates, crls, isAttach);
                break;
            case KEY_AGREEMENT_INFO_DATA:
                break;
            case ENCRYPTED_DATA:
                break;
            case ENVELOPED_DATA:
                break;
            case SIGNED_AND_ENVELOPED_DATA:
                break;
        }
        return new ContentInfo(infoTypeEnum.getOid(), asn1Encodable);
    }


    private ASN1OctetString genData(byte[] data) {
        return BytesUtil.isBlank(data) ? null : new DEROctetString(data);
    }

    /**
     * @param []
     * @return com.github.zhenwei.core.asn1.DEROctetString
     * @author zhangzhenwei
     * @description
     * SignedData ::= SEQUENCE {
     *       version Version, --版本
     *       digestAlgorithms DigestAlgorithmIdentifiers, -- set of DigestAlgorithmIdentifier 摘要算法
     *       contentInfo ContentInfo, -- 被签名的数据，原文，同 Data类型
     *       certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
     *              --set of ExtendedCertificateOrCertificate ，证书
     *       crls [1] IMPLICIT CertificateRevocationLists OPTIONAL, -- crl
     *       signerInfos SignerInfos  --签名数据
     *       }
     * @date 2022/3/3  9:46 下午
     * @since: 1.0.0
     */
    private ASN1Encodable genSignedData(byte[] data, SignAlgEnum signAlgEnum, byte[] signature, Certificate[] certificates,
                                        X509CRL[] crls, boolean isAttach) throws WeGooCryptoException {
        try {
            certificates = certificates == null ? new Certificate[0] : certificates;
            crls = crls == null ? new X509CRL[0] : crls;
            Version version = new Version(1);
            DERSet digestAlgorithms = new DERSet(signAlgEnum.getDigestAlgEnum().getOid());
            if (!isAttach) {
                data = null;
            }
            //若包含原文则填充原文
            ContentInfo contentInfo = build(GmPkcs7ContentInfoTypeEnum.DATA, data, signAlgEnum, null, null, null, isAttach);
            DERSet setOfCerts = new DERSet(certificates);
            ASN1EncodableVector crlVector = new ASN1EncodableVector();
            for (X509CRL crl : crls) {
                crlVector.add(new ASN1InputStream(crl.getEncoded()).readObject());
            }
            DERSet setOfCrls = new DERSet(crlVector);

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

            // 构造signerInfo
            IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(certificates[0].getSubject(),
                    certificates[0].getSerialNumber().getPositiveValue());
            AlgorithmIdentifier hashId = new AlgorithmIdentifier(signAlgEnum.getDigestAlgEnum().getOid());
            AlgorithmIdentifier signId = new AlgorithmIdentifier(signAlgEnum.getOid());
            //没有填充 authenticatedAttributes，unauthenticatedAttributes
            SignerInfo signerInfo = new SignerInfo(version, issuerAndSerialNumber, hashId, null,
                    signId, new DEROctetString(signature), null);
            ASN1EncodableVector signerInfosVector = new ASN1EncodableVector();
            signerInfosVector.add(signerInfo);
            DERSet setOfSignerInfo = new DERSet(signerInfosVector);
            return new SignedData(version, digestAlgorithms, contentInfo, setOfCerts, setOfCrls, setOfSignerInfo);
        } catch (Exception e) {
            throw new WeGooCryptoException(CryptoExceptionMassageEnum.generate_signed_data_err, e);
        }
    }


    public byte[] enveloped(X509Certificate certificate, byte[] data) throws BaseWeGooException, IOException {
        ASN1EncodableVector envelopedDataVector = new ASN1EncodableVector();
        ASN1EncodableVector recipientInfosVector = new ASN1EncodableVector();
        ASN1EncodableVector recipientInfoVector = new ASN1EncodableVector();
        ASN1EncodableVector encryptedContentInfoVector = new ASN1EncodableVector();
        ASN1Integer version = new ASN1Integer(0);
        envelopedDataVector.add(version);
        //版本
        recipientInfoVector.add(version);
        IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(new X500Name(certificate.getSubjectDN().getName()), certificate.getSerialNumber());
        //序列号
        recipientInfoVector.add(issuerAndSerialNumber);
        //匹配算法标识
        PublicKey publicKey = certificate.getPublicKey();
        String algorithm = publicKey.getAlgorithm();
        //todo 算法oid
        ASN1ObjectIdentifier identifier = GMObjectIdentifiers.sms4_cbc;
        boolean isEc = algorithm.equalsIgnoreCase("EC");
        ASN1ObjectIdentifier p7Oid = isEc ? new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.3") : ContentInfo.envelopedData;
        //RSA/SM2加解密算法
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(identifier);
        recipientInfoVector.add(algorithmIdentifier);
        WeGooProvider provider = new WeGooProvider();
        KeyBuilder keyBuilder = new KeyBuilder(provider);
        Key key = keyBuilder.buildKey(KeyEnum.SM4_128);
        CipherBuilder cipherBuilder = new CipherBuilder(provider);
        //加密
        byte[] encData = cipherBuilder.cipher(CipherAlgEnum.SM2, publicKey, key.getEncoded(), null, true);
        recipientInfoVector.add(new DEROctetString(encData));

        DERSequence recipientInfo = new DERSequence(recipientInfoVector);
        recipientInfosVector.add(recipientInfo);

        DERSet recipientInfos = new DERSet(recipientInfosVector);
        //recipientInfos
        envelopedDataVector.add(recipientInfos);
        //ContentType
        encryptedContentInfoVector.add(isEc ? new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.1") : ContentInfo.data);
        //contentEncryptionAlgorithm
        CipherAlgEnum encAlg = CipherAlgEnum.SM4_ECB_PKCS7Padding;
        ASN1ObjectIdentifier sms4_ecb = GMObjectIdentifiers.sms4_ecb;
        if (encAlg.getModeEnum().isNeedIV()) {
            //todo
            encryptedContentInfoVector.add(new AlgorithmIdentifier(sms4_ecb, new DEROctetString(new byte[16])));
        } else {
            encryptedContentInfoVector.add(new AlgorithmIdentifier(sms4_ecb));
        }
        //todo iv
        byte[] symEncData = cipherBuilder.cipher(encAlg, key, data, null, true);
        // encryptedContent
        encryptedContentInfoVector.add(new DERTaggedObject(false, 0, new BEROctetString(symEncData)));


//        DERSequence encryptedContentInfo = new DERSequence(encryptedContentInfoVector);
        BERSequence encryptedContentInfo = new BERSequence(encryptedContentInfoVector);
        //encryptedContentInfo
        envelopedDataVector.add(encryptedContentInfo);
        //envelopedData
        DERSequence envelopedData = new DERSequence(envelopedDataVector);
        return new ContentInfo(p7Oid, envelopedData).getEncoded(ASN1Encoding.BER);
    }

}
