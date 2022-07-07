package com.github.zhenwei.core.enums;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;

/**
 * @description: GmPkcs7ContentInfoTypeEnum
 *  PKCS7 国密 类型枚举，参考 GMT-0010
 *   ContentType: data, signedData, envelopedData, signedAndEnvelopedData, keyAgreementInfoData, and encryptedData
 * @author: zhangzhenwei
 * @since: 1.0.0
 * @date: 2022/3/1  7:08 下午
 */
public enum GmPkcs7ContentInfoTypeEnum implements BasePkcs7TypeEnum{
    DATA(GMObjectIdentifiers.data),
    SIGNED_DATA(GMObjectIdentifiers.signed_data),
    ENVELOPED_DATA(GMObjectIdentifiers.enveloped_data),
    SIGNED_AND_ENVELOPED_DATA(GMObjectIdentifiers.signed_and_enveloped_data),
    ENCRYPTED_DATA(GMObjectIdentifiers.encrypted_data),
    KEY_AGREEMENT_INFO_DATA(GMObjectIdentifiers.key_agreement_info_data),
    ;

    private ASN1ObjectIdentifier oid;

    GmPkcs7ContentInfoTypeEnum(ASN1ObjectIdentifier oid) {
        this.oid = oid;
    }

    public ASN1ObjectIdentifier getOid() {
        return oid;
    }
}
