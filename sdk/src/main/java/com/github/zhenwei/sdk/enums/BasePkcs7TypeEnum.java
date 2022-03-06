package com.github.zhenwei.sdk.enums;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;

public interface BasePkcs7TypeEnum extends BaseEnum {
    ASN1ObjectIdentifier getOid();
}