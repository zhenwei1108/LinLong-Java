package com.github.zhenwei.pkix.cms;



interface AuthAttributesProvider
{
    ASN1Set getAuthAttributes();

    boolean isAead();
}