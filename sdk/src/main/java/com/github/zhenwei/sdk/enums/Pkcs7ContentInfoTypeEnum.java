package com.github.zhenwei.sdk.enums;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * @description: Pkcs7ContentInfoTypeEnum
 *  PKCS7 类型枚举，参考 RFC-2315
 *   ContentType: data, signedData, envelopedData, signedAndEnvelopedData, digestedData, and encryptedData
 * @author: zhangzhenwei
 * @since: 1.0.0
 * @date: 2022/3/1  7:08 下午
 */
public enum Pkcs7ContentInfoTypeEnum implements BasePkcs7TypeEnum{
    DATA(PKCSObjectIdentifiers.data),
    SIGNED_DATA(PKCSObjectIdentifiers.signedData),
    ENVELOPED_DATA(PKCSObjectIdentifiers.envelopedData),
    SIGNED_AND_ENVELOPED_DATA(PKCSObjectIdentifiers.signedAndEnvelopedData),
    DIGESTED_DATA(PKCSObjectIdentifiers.digestedData),
    ENCRYPTED_DATA(PKCSObjectIdentifiers.encryptedData),
    ;

    private ASN1ObjectIdentifier oid;

    Pkcs7ContentInfoTypeEnum(ASN1ObjectIdentifier oid) {
        this.oid = oid;
    }

    public ASN1ObjectIdentifier getOid() {
        return oid;
    }
}
