package com.github.zhenwei.sdk.builder.pkcs7;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.pkcs.ContentInfo;
import com.github.zhenwei.core.asn1.x509.Certificate;
import com.github.zhenwei.core.enums.BasePkcs7TypeEnum;
import com.github.zhenwei.core.enums.SignAlgEnum;
import com.github.zhenwei.core.exception.WeGooCryptoException;
import com.github.zhenwei.core.exception.WeGooEnvelopException;
import com.github.zhenwei.sdk.util.ArrayUtils;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

public abstract class AbstractPkcs7Builder {


    public ContentInfo genPkcs7ContentInfo(BasePkcs7TypeEnum infoTypeEnum, byte[] data, SignAlgEnum signAlgEnum,
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

    abstract ASN1Encodable genSignedData(byte[] data, SignAlgEnum signAlgEnum, byte[] signature,
                                         Certificate[] certificates, X509CRL[] crls, boolean isAttach) throws WeGooCryptoException;

    abstract ASN1Encodable enveloped(X509Certificate certificate, byte[] data) throws WeGooEnvelopException;
}
