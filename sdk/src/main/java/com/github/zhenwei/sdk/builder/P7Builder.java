package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.pkcs.ContentInfo;
import com.github.zhenwei.sdk.enums.BasePkcs7TypeEnum;
import com.github.zhenwei.sdk.enums.GmPkcs7ContentInfoTypeEnum;
import com.github.zhenwei.sdk.enums.Pkcs7ContentInfoTypeEnum;
import com.github.zhenwei.sdk.exception.WeGooCipherException;

/**
 * @description: P7Builder
 * pkcs 7 构造者， 包含： 签名，信封
 * 参考 RFC-2315(p7) RFC-3852(CMS)
 * @author: zhangzhenwei
 * @since: 1.0.0
 * @date: 2022/2/28  10:32 下午
 */
public class P7Builder {

    public P7Builder getInstance(Object obj) {
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
    public ContentInfo build(BasePkcs7TypeEnum typeEnum, byte[] data) throws WeGooCipherException {
        ContentInfo contentInfo;
        //根据枚举类型判断是否为国密类型。国密类型OID 有另定义
        if (typeEnum instanceof Pkcs7ContentInfoTypeEnum) {
            Pkcs7ContentInfoTypeEnum infoTypeEnum = (Pkcs7ContentInfoTypeEnum) typeEnum;
            contentInfo = genPkcs7ContentInfo(infoTypeEnum, data);
        } else if (typeEnum instanceof GmPkcs7ContentInfoTypeEnum) {
            GmPkcs7ContentInfoTypeEnum infoTypeEnum = (GmPkcs7ContentInfoTypeEnum) typeEnum;
            contentInfo = genGmPkcs7ContentInfo(infoTypeEnum, data);
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


    private ContentInfo genGmPkcs7ContentInfo(GmPkcs7ContentInfoTypeEnum infoTypeEnum, byte[] data) {
        ASN1Encodable asn1Encodable = null;
        switch (infoTypeEnum) {
            case DATA:
                asn1Encodable = genData(data);
                break;
            case SIGNED_DATA:
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
     * @description 
     *     SignedData ::= SEQUENCE {
     *        version Version,
     *        digestAlgorithms DigestAlgorithmIdentifiers,
     *        contentInfo ContentInfo,
     *        certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
     *        crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
     *        signerInfos SignerInfos
     *        }
     * @date 2022/3/3  9:46 下午
     * @since: 
     */
//    private DEROctetString genSm2SignedData(SignAlgEnum signAlgEnum, Sm2Signature signature,){
//        ASN1Integer version = new ASN1Integer(1);
//        DigestAlgEnum digestAlgEnum = signAlgEnum.getDigestAlgEnum();
//        DERSet digestAlgorithms = new DERSet(digestAlgEnum.getOid());
//        ContentInfo contentInfo = ContentInfo.getInstance(signature.getEncoded());
//        SignedData signedData = new SignedData(version,digestAlgorithms,contentInfo,);
//
//    }
//
    
}
