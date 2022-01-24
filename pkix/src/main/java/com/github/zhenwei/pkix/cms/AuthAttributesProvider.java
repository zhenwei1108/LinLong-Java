package com.github.zhenwei.pkix.cms;

import com.github.zhenwei.core.asn1.ASN1Set;

interface AuthAttributesProvider
{
    ASN1Set getAuthAttributes();

    boolean isAead();
}