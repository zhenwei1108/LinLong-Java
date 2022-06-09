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
import com.github.zhenwei.core.exception.WeGooCipherException;
import com.github.zhenwei.core.exception.WeGooCryptoException;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;

import java.io.IOException;
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
    public ContentInfo build(BasePkcs7TypeEnum typeEnum, byte[] data) throws WeGooCryptoException {
        ContentInfo contentInfo;
        //根据枚举类型判断是否为国密类型。国密类型OID 有另定义
        if (typeEnum instanceof Pkcs7ContentInfoTypeEnum) {
            Pkcs7ContentInfoTypeEnum infoTypeEnum = (Pkcs7ContentInfoTypeEnum) typeEnum;
            contentInfo = genPkcs7ContentInfo(infoTypeEnum, data);
        } else if (typeEnum instanceof GmPkcs7ContentInfoTypeEnum) {
            GmPkcs7ContentInfoTypeEnum infoTypeEnum = (GmPkcs7ContentInfoTypeEnum) typeEnum;
            contentInfo = genGmPkcs7ContentInfo(infoTypeEnum, data, null, null, null, null);
        } else {
            throw new WeGooCipherException("");
        }
        return contentInfo;


    }


    private ContentInfo genPkcs7ContentInfo(Pkcs7ContentInfoTypeEnum infoTypeEnum, byte[] data) {
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
                                              SignAlgEnum signAlgEnum, byte[] signature, Certificate[] certificates, X509CRL[] crls)
            throws WeGooCryptoException {
        ASN1Encodable asn1Encodable = null;
        switch (infoTypeEnum) {
            case DATA:
                asn1Encodable = genData(data);
                break;
            case SIGNED_DATA:
                asn1Encodable = genSignedData(signAlgEnum, signature, certificates, crls);
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


    private DEROctetString genData(byte[] data) {
        return new DEROctetString(data);
    }

    /**
     * @param []
     * @return com.github.zhenwei.core.asn1.DEROctetString
     * @author zhangzhenwei
     * @description SignedData ::= SEQUENCE {
     * version Version,
     * digestAlgorithms DigestAlgorithmIdentifiers, -- set of DigestAlgorithmIdentifier
     * contentInfo ContentInfo,
     * certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL, --set of ExtendedCertificateOrCertificate
     * crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
     * signerInfos SignerInfos
     * }
     * @date 2022/3/3  9:46 下午
     * @since: 1.0.0
     */
    private ASN1Encodable genSignedData(SignAlgEnum signAlgEnum, byte[] signature, Certificate[] certificates,
                                           X509CRL[] crls) throws WeGooCryptoException {
        try {
            Version version = new Version(1);
            DERSet digestAlgorithms = new DERSet(signAlgEnum.getDigestAlgEnum().getOid());
            ContentInfo contentInfo = ContentInfo.getInstance(signature);
            DERSet setOfCerts = new DERSet(certificates);
            ASN1EncodableVector crlVector = new ASN1EncodableVector();
            for (X509CRL crl : crls) {
                crlVector.add(new ASN1InputStream(crl.getEncoded()).readObject());
            }
            DERSet setOfCrls = new DERSet(crlVector);
            /**
             * SignerInfo ::= SEQUENCE {
             *      version Version,
             *      issuerAndSerialNumber IssuerAndSerialNumber,
             *      digestAlgorithm DigestAlgorithmIdentifier,
             *      authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
             *      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
             *      encryptedDigest EncryptedDigest,
             *      unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL }
             */
            SignerInfo signerInfo = SignerInfo.getInstance(null);
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