package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.asn1.ASN1InputStream;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.sdk.exception.WeGooCryptoException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class CertBuilder {

  public static Certificate getInstance(Object obj) throws WeGooCryptoException {
    try {
      CertificateFactory factory = CertificateFactory.getInstance("X.509", new WeGooProvider());
      if (obj instanceof Certificate) {
        return (Certificate) obj;
      } else if (obj instanceof InputStream) {
        return factory.generateCertificate((InputStream) obj);
      } else if (obj instanceof byte[]) {
        return factory.generateCertificate(new ASN1InputStream((byte[]) obj));
      }
      throw new WeGooCryptoException(CryptoExceptionMassageEnum.params_err);
    } catch (Exception e) {
      throw new WeGooCryptoException(CryptoExceptionMassageEnum.build_err, e);
    }
  }


}