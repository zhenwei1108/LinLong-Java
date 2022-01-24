package com.github.zhenwei.pkix.cms;

import java.io.IOException;
import java.io.InputStream;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;

interface CMSSecureReadable
{
    ASN1ObjectIdentifier getContentType();

    InputStream getInputStream()
            throws IOException, CMSException;
}