package com.github.zhenwei.pkix.cert;

import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.pkix.operator.ContentVerifierProvider;
import com.github.zhenwei.pkix.operator.OperatorCreationException;

public interface X509ContentVerifierProviderBuilder {

  ContentVerifierProvider build(SubjectPublicKeyInfo validatingKeyInfo)
      throws OperatorCreationException;

  ContentVerifierProvider build(X509CertificateHolder validatingKeyInfo)
      throws OperatorCreationException;
}