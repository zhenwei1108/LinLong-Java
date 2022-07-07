package com.github.zhenwei.pkix.cms;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import java.io.IOException;
import java.io.InputStream;

interface CMSSecureReadable {

  ASN1ObjectIdentifier getContentType();

  InputStream getInputStream()
      throws IOException, CMSException;
}