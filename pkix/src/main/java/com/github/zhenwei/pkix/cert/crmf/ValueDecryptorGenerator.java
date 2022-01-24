package com.github.zhenwei.pkix.cert.crmf;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import  com.github.zhenwei.pkix.operator.InputDecryptor;

public interface ValueDecryptorGenerator
{
    InputDecryptor getValueDecryptor(AlgorithmIdentifier keyAlg, AlgorithmIdentifier symmAlg, byte[] encKey)
        throws CRMFException;
}