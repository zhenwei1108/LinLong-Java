package com.github.zhenwei.pkix.pkix.jcajce;

import java.security.cert.CertPathValidatorException;

class CRLNotFoundException
    extends CertPathValidatorException
{
    CRLNotFoundException(String message)
    {
        super(message);
    }

    public CRLNotFoundException(String message, Throwable cause)
    {
        super(message, cause);
    }
}