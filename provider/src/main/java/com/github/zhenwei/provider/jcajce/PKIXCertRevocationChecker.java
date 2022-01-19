package com.github.zhenwei.provider.jcajce;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;

public interface PKIXCertRevocationChecker
{
    void setParameter(String name, Object value);

    void initialize(PKIXCertRevocationCheckerParameters params)
        throws CertPathValidatorException;

    void check(Certificate cert)
        throws CertPathValidatorException;
}