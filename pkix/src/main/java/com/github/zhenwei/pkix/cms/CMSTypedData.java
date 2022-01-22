package com.github.zhenwei.pkix.cms;



public interface CMSTypedData
    extends CMSProcessable
{
    ASN1ObjectIdentifier getContentType();
}