package com.github.zhenwei.pkix.cert.path.validations;

import com.github.zhenwei.pkix.cert.X509CertificateHolder;

class ValidationUtils
{
    static boolean isSelfIssued(X509CertificateHolder cert)
    {
        return cert.getSubject().equals(cert.getIssuer());
    }
}