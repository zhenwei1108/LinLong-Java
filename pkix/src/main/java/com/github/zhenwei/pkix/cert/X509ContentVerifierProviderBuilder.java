package com.github.zhenwei.pkix.cert;


import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;

public interface X509ContentVerifierProviderBuilder
{
    ContentVerifierProvider build(SubjectPublicKeyInfo validatingKeyInfo)
        throws OperatorCreationException;

    ContentVerifierProvider build(X509CertificateHolder validatingKeyInfo)
        throws OperatorCreationException;
}