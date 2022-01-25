package com.github.zhenwei.pkix.cert.path;

import com.github.zhenwei.core.util.Memoable;
import com.github.zhenwei.pkix.cert.X509CertificateHolder;

public interface CertPathValidation
    extends Memoable {

  public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
      throws CertPathValidationException;
}