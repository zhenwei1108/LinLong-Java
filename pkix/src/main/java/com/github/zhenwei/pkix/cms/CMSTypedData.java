package com.github.zhenwei.pkix.cms;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;

public interface CMSTypedData
    extends CMSProcessable {

  ASN1ObjectIdentifier getContentType();
}