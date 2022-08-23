package com.github.zhenwei.core.enums;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;

/**
 * @description: BasePkcs7TypeEnum
 *  PKCS类型
 * @author: zhangzhenwei
 * @since:1.0.0
 * @date: 2022/8/10  22:53
 */
public interface BasePkcs7TypeEnum extends BaseEnum {
    ASN1ObjectIdentifier getOid();

    String DATA = "DATA";
    String SIGNED_DATA = "SIGNED_DATA";
    String KEY_AGREEMENT_INFO_DATA = "KEY_AGREEMENT_INFO_DATA";
    String ENCRYPTED_DATA = "ENCRYPTED_DATA";
    String ENVELOPED_DATA = "ENVELOPED_DATA";
    String SIGNED_AND_ENVELOPED_DATA = "SIGNED_AND_ENVELOPED_DATA";



}
