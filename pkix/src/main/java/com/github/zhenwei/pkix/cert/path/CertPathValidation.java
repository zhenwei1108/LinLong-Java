package com.github.zhenwei.pkix.cert.path;

import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import com.github.zhenwei.core.util.Memoable;

public interface CertPathValidation
    extends Memoable
{
    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException;
}