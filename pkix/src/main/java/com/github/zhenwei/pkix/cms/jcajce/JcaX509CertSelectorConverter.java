package com.github.zhenwei.pkix.cms.jcajce;

import com.github.zhenwei.pkix.cms.KeyTransRecipientId;
import com.github.zhenwei.pkix.cms.SignerId;
import java.security.cert.X509CertSelector;

public class JcaX509CertSelectorConverter
    extends com.github.zhenwei.pkix.cert.selector.jcajce.JcaX509CertSelectorConverter {

  public JcaX509CertSelectorConverter() {
  }

  public X509CertSelector getCertSelector(KeyTransRecipientId recipientId) {
    return doConversion(recipientId.getIssuer(), recipientId.getSerialNumber(),
        recipientId.getSubjectKeyIdentifier());
  }

  public X509CertSelector getCertSelector(SignerId signerId) {
    return doConversion(signerId.getIssuer(), signerId.getSerialNumber(),
        signerId.getSubjectKeyIdentifier());
  }
}