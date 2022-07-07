package com.github.zhenwei.pkix.pkcs.bc;

import com.github.zhenwei.core.asn1.pkcs.CertificationRequest;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.util.PublicKeyFactory;
import com.github.zhenwei.pkix.pkcs.PKCS10CertificationRequest;
import com.github.zhenwei.pkix.pkcs.PKCSException;
import java.io.IOException;

public class BcPKCS10CertificationRequest
    extends PKCS10CertificationRequest {

  public BcPKCS10CertificationRequest(CertificationRequest certificationRequest) {
    super(certificationRequest);
  }

  public BcPKCS10CertificationRequest(byte[] encoding)
      throws IOException {
    super(encoding);
  }

  public BcPKCS10CertificationRequest(PKCS10CertificationRequest requestHolder) {
    super(requestHolder.toASN1Structure());
  }

  public AsymmetricKeyParameter getPublicKey()
      throws PKCSException {
    try {
      return PublicKeyFactory.createKey(this.getSubjectPublicKeyInfo());
    } catch (IOException e) {
      throw new PKCSException("error extracting key encoding: " + e.getMessage(), e);
    }
  }
}