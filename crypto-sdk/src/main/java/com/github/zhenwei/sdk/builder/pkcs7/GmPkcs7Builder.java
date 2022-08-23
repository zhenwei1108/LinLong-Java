package com.github.zhenwei.sdk.builder.pkcs7;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.exception.WeGooEnvelopException;
import java.security.cert.X509Certificate;

public class GmPkcs7Builder extends AbstractPkcs7Builder{

  @Override
  ASN1Encodable enveloped(X509Certificate certificate, byte[] data) throws WeGooEnvelopException {
    return null;
  }

}
